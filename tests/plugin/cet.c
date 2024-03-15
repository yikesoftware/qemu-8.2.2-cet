#include <inttypes.h>
#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdio.h>
#include <signal.h>
#include <glib.h>
#include <pthread.h>

#include <qemu-plugin.h>

QEMU_PLUGIN_EXPORT int qemu_plugin_version = QEMU_PLUGIN_VERSION;

//static bool cet_debug = true;
//#define CET_DEBUG (cet_debug)

#define likely(x)       __builtin_expect((x),1)
#define unlikely(x)     __builtin_expect((x),0)

#define MAX_CPUS 8
#define LOG_PREFIX "[CET] "
#define LOG_PREFIX_QEMU "[QEMU] "
#define LOG_PREFIX_IBT "[CET-IBT] "
#define LOG_PREFIX_SS "[CET-SS] "
#define LOG_PREFIX_ERROR "[CET-ERR] "
#define LOG_PREFIX_CALLBACK "[CALLBACK] "

static uint32_t cpu_count;
#define DEFAULT_CPU_SLOTS 16
#define MIN_CPU_SLOTS 1
#define MAX_CPU_SLOTS 4096
static uint32_t cpu_slots = DEFAULT_CPU_SLOTS;
// cpu oprations lock
static pthread_mutex_t cpu_lock = PTHREAD_MUTEX_INITIALIZER;

# define ARCH_CET_STATUS	    0x3001
# define ARCH_CET_DISABLE	    0x3002
# define ARCH_CET_LOCK		    0x3003
# define ARCH_CET_ALLOC_SHSTK	0x3004
#define GNU_PROPERTY_X86_FEATURE_1_IBT		(1U << 0)
#define GNU_PROPERTY_X86_FEATURE_1_SHSTK	(1U << 1)
//QEMU_PLUGIN_EXPORT uint64_t cet_status = 0x100;

const char *plugin_mode;
#define IS_USER_MODE() (g_strcmp0(plugin_mode, "user") == 0)
#define IS_SYSTEM_MODE() (g_strcmp0(plugin_mode, "system") == 0)

static bool cet_ibt_enable = true;
static bool cet_ss_enable = true;
#define IBT_ENABLED() (cet_ibt_enable)
#define SS_ENABLED() (cet_ss_enable)
static int cet_ibt_start = 0;
static int cet_ss_start = 0;
#define IBT_START() (cet_ibt_start)
#define SS_START() (cet_ss_start)

typedef struct {
    uint64_t vaddr;
    uint64_t size;
    uint8_t *bytes;
    char *disas;
} Instruction;


/* IBT */
enum {
    IBT_DISABLED,
    IBT_IDLE,
    IBT_WAIT_ENDBRANCH,
    IBT_ERROR
} e_ibt_states;
typedef struct {
    uint32_t state;
    uint32_t bits;
    Instruction *from_insn;
} ibt_state_t;
static ibt_state_t *ibt_states_percpu;
#define IS_ENDBR32(disas) (g_str_has_prefix(disas, "endbr32"))
#define IS_ENDBR64(disas) (g_str_has_prefix(disas, "endbr64"))
#define IS_ARCH_ENDBR(ibt_state, disas) (ibt_state->bits == 32 ? IS_ENDBR32(disas) : IS_ENDBR64(disas))
#define IS_CALL(_disas_str) (g_str_has_prefix((_disas_str), "call"))
#define IS_JMP(_disas_str) (g_str_has_prefix((_disas_str), "jmp"))
#define HAS_NOTACK(insn_bytes) (((uint8_t *)(insn_bytes))[0] == 0xe3)
#define IS_INDIR_CALL(_disas_str, insn_bytes) (                                                                         \
            IS_CALL(_disas_str) &&                                                                                      \
            (HAS_NOTACK(insn_bytes) ? (((uint8_t *)(insn_bytes))[1] == 0xff) : (((uint8_t *)(insn_bytes))[0] == 0xff))  \
        )
#define IS_INDIR_JMP(_disas_str, insn_bytes) (                                                                          \
            IS_JMP(_disas_str) &&                                                                                       \
            (HAS_NOTACK(insn_bytes) ? (((uint8_t *)(insn_bytes))[1] == 0xff) : (((uint8_t *)(insn_bytes))[0] == 0xff))  \
        )
/* end IBT */


/* SHSTK */
enum {
    SS_DISABLED,
    SS_IDLE,
    SS_RETURN,
    SS_ERROR
} e_ss_states;
typedef struct {
    uint32_t state;
    int64_t SSP;
    struct vector {
        uint64_t size;
        uint64_t capacity;
        uint64_t *ret_addrs;
        Instruction *call_insn;
    } stk_vec;
} shadow_stack_t;
static shadow_stack_t *ss_percpu;
#define IS_RET(_disas_str) (g_str_has_prefix(_disas_str, "ret"))
#define INIT_SHSTK_SIZE 0x10
#define SHSTK_PUSH(_ss, _n_call_i, _n_ret) ({                                                       \
    uint64_t _ret = -1;                                                                             \
    assert((_ss)->SSP >= -1);                                                                       \
    assert((_ss)->stk_vec.ret_addrs != NULL && (_ss)->stk_vec.call_insn != NULL);                   \
    if((_ss)->stk_vec.size == (_ss)->stk_vec.capacity){                                                          \
        uint64_t new_capacity = (_ss)->stk_vec.capacity * 2;                                                     \
        (_ss)->stk_vec.capacity *= new_capacity;                                                                 \
        (_ss)->stk_vec.ret_addrs = g_realloc((_ss)->stk_vec.ret_addrs, new_capacity*sizeof(int64_t));            \
        (_ss)->stk_vec.call_insn = g_realloc((_ss)->stk_vec.call_insn, new_capacity*sizeof(Instruction));        \
        assert((_ss)->stk_vec.ret_addrs != NULL && (_ss)->stk_vec.call_insn != NULL);                            \
    }                                                                                                            \
    (_ss)->stk_vec.ret_addrs[++(_ss)->SSP] = (_n_ret);                              \
    (_ss)->stk_vec.call_insn[(_ss)->SSP].vaddr = (_n_call_i)->vaddr;                \
    (_ss)->stk_vec.call_insn[(_ss)->SSP].size = (_n_call_i)->size;                  \
    (_ss)->stk_vec.call_insn[(_ss)->SSP].disas = g_strdup((_n_call_i)->disas);      \
    (_ss)->stk_vec.size++;   \
    _ret = 0;                \
    _ret;                    \
})
#define SHSTK_POP(_ss) ({                                                                                   \
    uint64_t _ret = -1;                                                                                     \
    assert((_ss)->SSP >= 0);                                                                        \
    assert((_ss)->stk_vec.ret_addrs != NULL && (_ss)->stk_vec.call_insn != NULL);                   \
    if((_ss)->stk_vec.size > 0){                                                                    \
        g_free((_ss)->stk_vec.call_insn[(_ss)->SSP].disas);                                         \
        (_ss)->stk_vec.size--;                                                                      \
        (_ss)->SSP--;                                                                               \
        _ret = 0;                                                                                           \
    }                                                                                                       \
    _ret;                                                                                                   \
})
#define DUMP_SHSTK(_ss) ({                                                                                                  \
    char _dumpstk_disas_internal_buf[0x100] = {0};                                                                          \
    for(int i = (_ss)->SSP; i >= 0; i--){                                                                                   \
        char *disas_res = plugin_disas_hack((_ss)->stk_vec.call_insn[i].vaddr+(_ss)->stk_vec.call_insn[i].size);            \
        if(disas_res){                                                                                                      \
            snprintf(_dumpstk_disas_internal_buf, 0x100, "%s", disas_res);                                                  \
            g_free(disas_res);                                                                                              \
        } else{                                                                                                             \
            snprintf(_dumpstk_disas_internal_buf, 0x100, "Hacking disasm failed: no capstone?");                            \
        }                                                                                                                   \
        if(unlikely(i == (_ss)->SSP)){                                                                                      \
            qemu_plugin_outs(g_strdup_printf("\tSSP =>\t| %d | 0x%lx |\t/* %s */\n",                                        \
                i, (_ss)->stk_vec.ret_addrs[i], _dumpstk_disas_internal_buf));                                              \
        } else {                                                                                                            \
            qemu_plugin_outs(g_strdup_printf("\t      \t| %d | 0x%lx |\t/* %s */\n",                                        \
                i, (_ss)->stk_vec.ret_addrs[i], _dumpstk_disas_internal_buf));                                              \
        }                                                                                                                   \
    }                                                                                                                       \
})
/* end SHSTK */

/* SUB-CALLBACK */
enum {
    CET_CB_BB_DUMMY,
    CET_CB_BB_ENTRY,
    CET_CB_JMP,
    CET_CB_CALL,
    CET_CB_RET
};
typedef struct cet_cb_t {
    float priority;     // must be unique and not zero!!!
    uint32_t cb_type;
    void *udata;
    struct cet_cb_t *next;
} cet_cb_t;
typedef struct {
    uint64_t vaddr;
    cet_cb_t *cet_cbs;
} cet_cb_ctx_t;
/* end SUB-CALLBACK */


#define infinite_loop() \
    do {                \
        for(;;)         \
            ;           \
    } while(0)

/* Fuck qemu! Why not give me a single disas API or just give me the fucking CPUState */
char *plugin_disas_hack(uint64_t addr);
char *plugin_disas_hack(uint64_t addr)
{
    struct _GByteArray ba;
    struct hack_insn{
        struct _GByteArray *data;
        uint64_t vaddr;
    } tmp_insn;
    tmp_insn.vaddr = addr;
    tmp_insn.data = &ba;
    tmp_insn.data->len = 15;
    char *res = qemu_plugin_insn_disas((const struct qemu_plugin_insn *)&tmp_insn);
    return res;
}


static void force_thread_sig(int sig){
    signal(sig, SIG_DFL);
    pthread_kill(pthread_self(), sig);

}

static void cet_ibt_violation_handler(ibt_state_t *ibt_state){
    if(IBT_START()){
        force_thread_sig(SIGSEGV);
        infinite_loop();
    } else{
        // resume is not started
        ibt_state->state = IBT_IDLE;
    }
}

static void cet_ss_violation_handler(shadow_stack_t *ss){
    if(SS_START()){
        force_thread_sig(SIGSEGV);
        infinite_loop();
    } else{
        // resume is not started
        ss->state = SS_IDLE;
    }
}

static void plugin_exit_cb(qemu_plugin_id_t id, void *p){
    qemu_plugin_outs(g_strdup_printf(LOG_PREFIX_QEMU "CET plugin exit.\n"));
    pthread_mutex_lock(&cpu_lock);
    if(IBT_ENABLED() && ibt_states_percpu){
        for(int i = 0; i < cpu_slots; i++){
            if(ibt_states_percpu[i].from_insn){
                if(ibt_states_percpu[i].from_insn->disas){
                    g_free(ibt_states_percpu[i].from_insn->disas);
                }
                g_free(ibt_states_percpu[i].from_insn);
                ibt_states_percpu[i].from_insn = NULL;
            }
        }
        g_free(ibt_states_percpu);
        ibt_states_percpu = NULL;
    }
    if(SS_ENABLED() && ss_percpu){
        for(int i = 0; i < cpu_slots; i++){
            if(ss_percpu[i].stk_vec.ret_addrs){
                g_free(ss_percpu[i].stk_vec.ret_addrs);
                ss_percpu[i].stk_vec.ret_addrs = NULL;
            }
            if(ss_percpu[i].stk_vec.call_insn){
                for(int j = 0; j < ss_percpu[i].stk_vec.size; j++){
                    if(ss_percpu[i].stk_vec.call_insn[j].disas){
                        g_free(ss_percpu[i].stk_vec.call_insn[j].disas);
                        ss_percpu[i].stk_vec.call_insn[j].disas = NULL;
                    }
                }
                g_free(ss_percpu[i].stk_vec.call_insn);
                ss_percpu[i].stk_vec.call_insn = NULL;
            }
        }
        g_free(ss_percpu);
        ss_percpu = NULL;
    }
    pthread_mutex_unlock(&cpu_lock);
}

static void cpu_init_cb(qemu_plugin_id_t id, unsigned int vcpu_index){
    qemu_plugin_outs(g_strdup_printf(LOG_PREFIX_QEMU "vCPU %d init\n", vcpu_index));
    pthread_mutex_lock(&cpu_lock);
    if(IBT_ENABLED()){
        ibt_state_t *ibt_state = &ibt_states_percpu[vcpu_index];
        ibt_state->state = IBT_IDLE;
        ibt_state->from_insn = NULL;
    }
    if(SS_ENABLED()){
        shadow_stack_t *ss = &ss_percpu[vcpu_index];
        ss->state = SS_IDLE;
        ss->SSP = -1;
        ss->stk_vec.size = 0;
        ss->stk_vec.capacity = INIT_SHSTK_SIZE;
        ss->stk_vec.ret_addrs = g_realloc(ss->stk_vec.ret_addrs, INIT_SHSTK_SIZE*sizeof(int64_t));
        ss->stk_vec.call_insn = g_realloc(ss->stk_vec.call_insn, INIT_SHSTK_SIZE*sizeof(Instruction));
        if(ss->stk_vec.ret_addrs == NULL || ss->stk_vec.call_insn == NULL){
            qemu_plugin_outs(g_strdup_printf(LOG_PREFIX_SS "Failed to allocate shadow stack\n"));
            exit(1);
        }
    }
    pthread_mutex_unlock(&cpu_lock);
}

static void cpu_exit_cb(qemu_plugin_id_t id, unsigned int vcpu_index){
    qemu_plugin_outs(g_strdup_printf(LOG_PREFIX_QEMU "vCPU %d exit!\n", vcpu_index));
    pthread_mutex_lock(&cpu_lock);
    // reset IBT
    ibt_state_t *ibt_state = &ibt_states_percpu[vcpu_index];
    ibt_state->state = IBT_IDLE;
    if(ibt_state->from_insn){
        if(ibt_state->from_insn->disas){
            g_free(ibt_state->from_insn->disas);
        }
        g_free(ibt_state->from_insn);
        ibt_state->from_insn = NULL;
    }
    // reset SS
    shadow_stack_t *ss = &ss_percpu[vcpu_index];
    ss->state = SS_IDLE;
    ss->SSP = -1;
    if(ss->stk_vec.ret_addrs){
        g_free(ss->stk_vec.ret_addrs);
        ss->stk_vec.ret_addrs = NULL;
    }
    if(ss->stk_vec.call_insn){
        for(int i = 0; i < ss->stk_vec.size; i++){
            if(ss->stk_vec.call_insn[i].disas){
                g_free(ss->stk_vec.call_insn[i].disas);
                ss->stk_vec.call_insn[i].disas = NULL;
            }
        }
        g_free(ss->stk_vec.call_insn);
        ss->stk_vec.call_insn = NULL;
    }
    ss->stk_vec.size = 0;
    ss->stk_vec.capacity = 0;
    pthread_mutex_unlock(&cpu_lock);
}

#ifdef CET_HOOK_SYSCALL
static void vcpu_syscall_cb(qemu_plugin_id_t id, unsigned int vcpu_idx,
                         int64_t num, uint64_t a1, uint64_t a2,
                         uint64_t a3, uint64_t a4, uint64_t a5,
                         uint64_t a6, uint64_t a7, uint64_t a8)
{
    qemu_plugin_outs(g_strdup_printf(LOG_PREFIX "vCPU %d syscall(num=%ld, %#lx, %#lx, %#lx, %#lx, %#lx, %#lx, %#lx, %#lx)\n", 
        vcpu_idx, num, a1, a2, a3, a4, a5, a6, a7, a8));
}


static void vcpu_syscall_ret_cb(qemu_plugin_id_t id, unsigned int vcpu_idx,
                             int64_t num, int64_t ret)
{
    qemu_plugin_outs(g_strdup_printf(LOG_PREFIX "vCPU %d syscall %ld -> return 0x%lx\n", vcpu_idx, num, ret));
}
#endif

static int init_cet_ibt(void)
{
    ibt_states_percpu = g_new0(ibt_state_t, cpu_slots);
    for (int i = 0; i < cpu_slots; i++) {
        ibt_states_percpu[i].state = IBT_IDLE;
        ibt_states_percpu[i].from_insn = NULL;
    }
    cet_ibt_start = 1;
    qemu_plugin_outs(g_strdup_printf(LOG_PREFIX_IBT "Initialize CET-IBT\n"));
    return 0;
}

static int init_cet_ss(void)
{
    ss_percpu = g_new0(shadow_stack_t, cpu_slots);
    for (int i = 0; i < cpu_slots; i++) {
        ss_percpu[i].state = SS_IDLE;
        ss_percpu[i].SSP = -1;
        ss_percpu[i].stk_vec.ret_addrs = g_realloc(ss_percpu[i].stk_vec.ret_addrs, INIT_SHSTK_SIZE*sizeof(int64_t));
        ss_percpu[i].stk_vec.call_insn = g_realloc(ss_percpu[i].stk_vec.call_insn, INIT_SHSTK_SIZE*sizeof(Instruction));
        if(ss_percpu[i].stk_vec.ret_addrs == NULL || ss_percpu[i].stk_vec.call_insn == NULL){
            qemu_plugin_outs(g_strdup_printf(LOG_PREFIX_SS "Failed to allocate shadow stack\n"));
            return -1;
        }
        ss_percpu[i].stk_vec.size = 0;
        ss_percpu[i].stk_vec.capacity = INIT_SHSTK_SIZE;
    }
    cet_ss_start = 1;
    qemu_plugin_outs(g_strdup_printf(LOG_PREFIX_IBT "Initialize CET-SS\n"));
    return 0;
}

static void cet_cb_bb_entry(cet_cb_ctx_t *cb_ctx, unsigned int cpu_idx, void *udata)
{
    char disas_buf[0x30] = {0};
    Instruction *entry_insn = (Instruction *)udata;
    assert(entry_insn != NULL);
    // process IBT
    if(IBT_ENABLED()){
        ibt_state_t *ibt_state = &ibt_states_percpu[cpu_idx];
        if(ibt_state->state == IBT_WAIT_ENDBRANCH){
#ifdef CET_DEBUG 
            qemu_plugin_outs(g_strdup_printf(LOG_PREFIX_IBT "Entry insn - %s\n", entry_insn->disas));
#endif
            if(IS_ARCH_ENDBR(ibt_state, entry_insn->disas)){
                ibt_state->state = IBT_IDLE;
                ibt_state->from_insn->vaddr = 0;
                ibt_state->from_insn->disas = NULL;
                g_free(ibt_state->from_insn);
                ibt_state->from_insn = NULL;
            } else{
                // set IBT state to error
                ibt_state->state = IBT_ERROR;
                qemu_plugin_outs(g_strdup_printf(LOG_PREFIX_ERROR 
                    "!!! IBT violation (vCPU %d) \n\t- caller: 0x%lx\t/* %s */\n\t- callee: 0x%lx\t/* %s */\n",
                    cpu_idx,
                    ibt_state->from_insn->vaddr,
                    ibt_state->from_insn->disas,
                    entry_insn->vaddr,
                    entry_insn->disas));
                // set IBT last call to NULL
                ibt_state->from_insn->vaddr = 0;
                ibt_state->from_insn->disas = NULL;
                g_free(ibt_state->from_insn);
                ibt_state->from_insn = NULL;
                // raise SIGSEGV
                cet_ibt_violation_handler(ibt_state);
            }
        }
    }
    // process SS
    if(SS_ENABLED()){
        shadow_stack_t *ss = &ss_percpu[cpu_idx];
        if(ss->state == SS_RETURN){
            if(ss->SSP >= 0){
                uint64_t target_ret_addr = ss->stk_vec.ret_addrs[ss->SSP];
                if(target_ret_addr != entry_insn->vaddr){
                    // mismatched
                    ss->state = SS_ERROR;
                    char *target_disas_res = plugin_disas_hack(target_ret_addr);
                    if(target_disas_res){
                        snprintf(disas_buf, sizeof(disas_buf), "%s", target_disas_res);
                        g_free(target_disas_res);
                    } else{
                        snprintf(disas_buf, sizeof(disas_buf), "Hacking disasm failed: no capstone?");
                    }
                    qemu_plugin_outs(g_strdup_printf(
                        LOG_PREFIX_ERROR "SHSTK violation - Mismatched (vCPU %d)\n\t- target(√): 0x%lx\t/* %s */\n\t- actual(×): 0x%lx\t/* %s */\n\t- caller   : 0x%lx\t/* %s */\n", 
                        cpu_idx,
                        target_ret_addr,
                        disas_buf, 
                        entry_insn->vaddr,
                        entry_insn->disas,
                        ss->stk_vec.call_insn[ss->SSP].vaddr,
                        ss->stk_vec.call_insn[ss->SSP].disas));
                    qemu_plugin_outs(g_strdup_printf("\t*** DUMP SHSTK ***\n"));
                    DUMP_SHSTK(ss);
                    SHSTK_POP(ss);
                    cet_ss_violation_handler(ss);
                } else{
                    // matched
                    uint64_t res = SHSTK_POP(ss);
                    if(res){
                        ss->state = SS_ERROR;
                        qemu_plugin_outs(g_strdup_printf(LOG_PREFIX_ERROR "SHSTK pop failed! (vCPU %d)\n", cpu_idx));
                        cet_ss_violation_handler(ss);
                    } else{
                        ss->state = SS_IDLE;
#ifdef CET_DEBUG
                        char *target_disas_res = plugin_disas_hack(target_ret_addr);
                        if(target_disas_res){
                            snprintf(disas_buf, sizeof(disas_buf), "%s", target_disas_res);
                            g_free(target_disas_res);
                        } else{
                            snprintf(disas_buf, sizeof(disas_buf), "Hacking disasm failed: no capstone?");
                        }
                        qemu_plugin_outs(g_strdup_printf(LOG_PREFIX_ERROR "SHSTK Matched (vCPU %d): 0x%lx\t/* %s */\n", 
                            cpu_idx,
                            target_ret_addr,
                            disas_buf));
#endif           
                    }     
                }
            } else{
                ss->state = SS_ERROR;
                qemu_plugin_outs(g_strdup_printf(LOG_PREFIX_ERROR "SHSTK violation (vCPU %d) - SHSTK OOB\n\t- return to: 0x%lx\t/* %s */\n", 
                    cpu_idx,
                    entry_insn->vaddr,
                    entry_insn->disas));
                cet_ss_violation_handler(ss);
            }
        }
    }
}

static void cet_cb_call_insn(cet_cb_ctx_t *cb_ctx, unsigned int cpu_idx, void *udata)
{
    Instruction *call_insn = (Instruction *)udata;
    assert(call_insn != NULL);
    // process IBT
    if(IBT_ENABLED() && IS_INDIR_CALL(call_insn->disas, call_insn->bytes) && !HAS_NOTACK(call_insn->bytes)){
        ibt_state_t *ibt_state = &ibt_states_percpu[cpu_idx];
        ibt_state->from_insn = g_new0(Instruction, 1);
        ibt_state->from_insn->vaddr = call_insn->vaddr;
        ibt_state->from_insn->disas = g_strdup(call_insn->disas);
        ibt_state->from_insn->size = call_insn->size;
        if(ibt_state->state == IBT_IDLE){
            ibt_state->state = IBT_WAIT_ENDBRANCH;
            ibt_state->bits = g_str_has_prefix(ibt_state->from_insn->disas, "callq") ? 64 : 32;
#ifdef CET_DEBUG 
            qemu_plugin_outs(g_strdup_printf(LOG_PREFIX_IBT "Call insn (%d bits): 0x%lx\t/* %s */\n", 
                ibt_state->bits, ibt_state->from_insn->vaddr, ibt_state->from_insn->disas));
#endif
        } else{
            ibt_state->state = IBT_ERROR;
            ibt_state->from_insn->vaddr = 0;
            ibt_state->from_insn->disas = NULL;
            g_free(ibt_state->from_insn);
            ibt_state->from_insn = NULL;
            qemu_plugin_outs(g_strdup_printf(LOG_PREFIX_ERROR 
                    "!!! IBT violation (vCPU %d)  \n\t- Error IBT state on: 0x%lx\t%s\n",
                    cpu_idx,
                    call_insn->vaddr,
                    call_insn->disas));
            // raise SIGSEGV
            cet_ibt_violation_handler(ibt_state);
        }
    }
    // process SS
    if(SS_ENABLED()){
        shadow_stack_t *ss = &ss_percpu[cpu_idx];
#ifdef CET_DEBUG  
        qemu_plugin_outs(g_strdup_printf(LOG_PREFIX_SS "Call insn: 0x%lx\t/* %s */\n", call_insn->vaddr, call_insn->disas));
#endif 
        uint64_t ret_addr = call_insn->vaddr+call_insn->size;
        uint64_t res = SHSTK_PUSH(ss, call_insn, ret_addr);
        if(res){        
            qemu_plugin_outs(g_strdup_printf(LOG_PREFIX_SS "SHSTK push failed! (vCPU %d)\n", cpu_idx));
            cet_ss_violation_handler(ss);
        }
        
#ifdef CET_DEBUG    
        qemu_plugin_outs(g_strdup_printf(LOG_PREFIX_SS "SHSTK PUSH: 0x%lx\n", 
            ss->stk_vec.ret_addrs[ss->SSP]));
#endif 
#ifdef CET_DEBUG
        DUMP_SHSTK(ss);
#endif
    }
}

static void cet_cb_jmp_insn(cet_cb_ctx_t *cb_ctx, unsigned int cpu_idx, void *udata)
{
    Instruction *jmp_insn = (Instruction *)udata;
    if(IBT_ENABLED()){
        ibt_state_t *ibt_state = &ibt_states_percpu[cpu_idx];
        ibt_state->from_insn = g_new0(Instruction, 1);
        ibt_state->from_insn->vaddr = jmp_insn->vaddr;
        ibt_state->from_insn->disas = g_strdup(jmp_insn->disas);
        if(ibt_state->state == IBT_IDLE){
            ibt_state->state = IBT_WAIT_ENDBRANCH;
            ibt_state->bits = g_str_has_prefix(jmp_insn->disas, "jmpq") ? 64 : 32;
#ifdef CET_DEBUG
            qemu_plugin_outs(g_strdup_printf(LOG_PREFIX_IBT "Jmp insn (%d bits)- %s\n", ibt_state->bits, jmp_insn->disas));
#endif
        } else{
            ibt_state->state = IBT_ERROR;
            ibt_state->from_insn->vaddr = 0;
            ibt_state->from_insn->disas = NULL;
            g_free(ibt_state->from_insn);
            ibt_state->from_insn = NULL;
            qemu_plugin_outs(g_strdup_printf(LOG_PREFIX_ERROR 
                    "!!! IBT violation (vCPU %d)  \n\t- jumper: 0x%lx\t%s\n\t- jumpee: 0x%lx\t%s\n",
                    cpu_idx,
                    ibt_state->from_insn->vaddr,
                    ibt_state->from_insn->disas,
                    jmp_insn->vaddr,
                    jmp_insn->disas));
            // raise SIGSEGV
            cet_ibt_violation_handler(ibt_state);
        }
    }
}

static void cet_cb_ret_insn(cet_cb_ctx_t *cb_ctx, unsigned int cpu_idx, void *udata)
{
    if(SS_ENABLED()){
#ifdef CET_DEBUG 
        Instruction *ret_insn = (Instruction *)udata;
        qemu_plugin_outs(g_strdup_printf(LOG_PREFIX_SS "Ret insn - %s\n", ret_insn->disas));
#endif
        shadow_stack_t *ss = &ss_percpu[cpu_idx];
        ss->state = SS_RETURN;
        return;
    }
}

static void cet_cb_main(unsigned int cpu_idx, void *udata)
{
    cet_cb_ctx_t *cb_ctx = (cet_cb_ctx_t *)udata;
    cet_cb_t *cbs = cb_ctx->cet_cbs;
    if(cbs == NULL){
        return;
    }

    // dispatch cbs (cb priority in list is from min to max)
    cet_cb_t *_cb = cbs;
    while(_cb != NULL){
        switch(_cb->cb_type){
            case CET_CB_BB_ENTRY:
                cet_cb_bb_entry(cb_ctx, cpu_idx, _cb->udata);
                break;
            case CET_CB_JMP:
                cet_cb_jmp_insn(cb_ctx, cpu_idx, _cb->udata);
                break;
            case CET_CB_CALL:
                cet_cb_call_insn(cb_ctx, cpu_idx, _cb->udata);
                break;
            case CET_CB_RET:
                cet_cb_ret_insn(cb_ctx, cpu_idx, _cb->udata);
                break;
            default:
                break;
        }
        _cb = _cb->next;
    }
}

static void append_cet_cb_with_priority(cet_cb_ctx_t *cb_ctx, cet_cb_t *new_cb)
{
    /* from min to maxm do not change new_cb->priority */
    assert(cb_ctx != NULL);
    assert(new_cb->priority != 0);
    if(cb_ctx->cet_cbs == NULL){
        cb_ctx->cet_cbs = new_cb;
    } else{
        cet_cb_t *_cb = cb_ctx->cet_cbs;
        cet_cb_t *_prev = NULL;
        while(1){
            if(likely(_cb->priority > new_cb->priority)){
                /* append before if new priority is less */
                if(_prev == NULL){
                    new_cb->next = _cb;
                    cb_ctx->cet_cbs = new_cb;
                } else{
                    new_cb->next = _cb;
                    _prev->next = new_cb;
                }
                break;
            }
            _prev = _cb;
            _cb = _cb->next;
            /* append to last if no more next */
            if(unlikely(_cb == NULL)){
                _prev->next = new_cb;
                break;
            }
        }
    }
}

static void vcpu_tb_trans(qemu_plugin_id_t id, struct qemu_plugin_tb *tb){
    size_t n = qemu_plugin_tb_n_insns(tb);
    for (int i = 0; i < n; i++) {
        struct qemu_plugin_insn *insn = qemu_plugin_tb_get_insn(tb, i);
        const uint8_t *insn_bytes = qemu_plugin_insn_data(insn);
        uint64_t vaddr = qemu_plugin_insn_vaddr(insn);
//#define CET_SHOW_SYMBOL
#ifdef CET_SHOW_SYMBOL
        if(qemu_plugin_insn_symbol(insn))
            qemu_plugin_outs(g_strdup_printf(LOG_PREFIX "Symbol: %s\n", qemu_plugin_insn_symbol(insn)));
#endif
//#define CET_SHOW_ALL_INSN
#ifdef CET_SHOW_ALL_INSN
        char *insn_disas_tmp = qemu_plugin_insn_disas(insn);
        qemu_plugin_outs(g_strdup_printf(LOG_PREFIX "INSN: %s\n\t%lx: ", insn_disas_tmp, qemu_plugin_insn_vaddr(insn)));
        g_free(insn_disas_tmp);
        for(int j = 0; j < qemu_plugin_insn_size(insn); j++){
            qemu_plugin_outs(g_strdup_printf("%02x ", insn_bytes[j]));
        }
        qemu_plugin_outs(g_strdup_printf("\n"));
#endif
        uint32_t cb_set = 0;
        cet_cb_ctx_t *cb_ctx = g_new0(cet_cb_ctx_t, 1);
        char *insn_disas = qemu_plugin_insn_disas(insn);
        cb_ctx->vaddr = vaddr;
        /* first insn in tb */
        if (unlikely(i == 0)) {
            cet_cb_t *new_cb = g_new0(cet_cb_t, 1);
            new_cb->priority = 1.0;
            new_cb->cb_type = CET_CB_BB_ENTRY;
            Instruction *entry_insn = g_new0(Instruction, 1);
            entry_insn->vaddr = vaddr;
            entry_insn->disas = g_strdup(insn_disas);
            entry_insn->size = qemu_plugin_insn_size(insn);
            entry_insn->bytes = g_new0(uint8_t, entry_insn->size);
            memcpy(entry_insn->bytes, insn_bytes, entry_insn->size);
            new_cb->udata = entry_insn;
            new_cb->next = NULL;
            append_cet_cb_with_priority(cb_ctx, new_cb);
            cb_set = 1;
        }
        if (unlikely(IS_CALL(insn_disas))){
            cet_cb_t *new_cb = g_new0(cet_cb_t, 1);
            new_cb->priority = 1.1;
            new_cb->cb_type = CET_CB_CALL;
            Instruction *from_insn = g_new0(Instruction, 1);
            from_insn->vaddr = vaddr;
            from_insn->disas = g_strdup(insn_disas);
            from_insn->size = qemu_plugin_insn_size(insn);
            from_insn->bytes = g_new0(uint8_t, from_insn->size);
            memcpy(from_insn->bytes, insn_bytes, from_insn->size);
            new_cb->udata = from_insn;
            new_cb->next = NULL;
            append_cet_cb_with_priority(cb_ctx, new_cb);
            cb_set = 1;
        }
        if (unlikely(IS_INDIR_JMP(insn_disas, insn_bytes) && !HAS_NOTACK(insn_bytes))){
            cet_cb_t *new_cb = g_new0(cet_cb_t, 1);
            new_cb->priority = 1.1;
            new_cb->cb_type = CET_CB_JMP;
            Instruction *from_insn = g_new0(Instruction, 1);
            from_insn->vaddr = vaddr;
            from_insn->disas = g_strdup(insn_disas);
            from_insn->size = qemu_plugin_insn_size(insn);
            from_insn->bytes = g_new0(uint8_t, from_insn->size);
            memcpy(from_insn->bytes, insn_bytes, from_insn->size);
            new_cb->udata = from_insn;
            new_cb->next = NULL;
            append_cet_cb_with_priority(cb_ctx, new_cb);
            cb_set = 1;
        } else if(unlikely(IS_RET(insn_disas))){
            cet_cb_t *new_cb = g_new0(cet_cb_t, 1);
            new_cb->priority = 1.1;
            new_cb->cb_type = CET_CB_RET;
            Instruction *from_insn = g_new0(Instruction, 1);
            from_insn->vaddr = vaddr;
            from_insn->disas = g_strdup(insn_disas);
            from_insn->size = qemu_plugin_insn_size(insn);
            from_insn->bytes = g_new0(uint8_t, from_insn->size);
            memcpy(from_insn->bytes, insn_bytes, from_insn->size);
            new_cb->udata = from_insn;
            new_cb->next = NULL;
            append_cet_cb_with_priority(cb_ctx, new_cb);
            cb_set = 1;
        }
        if (unlikely(cb_set)){
            qemu_plugin_register_vcpu_insn_exec_cb(
                insn, cet_cb_main, QEMU_PLUGIN_CB_NO_REGS,
                cb_ctx);
        } else{
            g_free(cb_ctx);
        }
        g_free(insn_disas);
    }
}

QEMU_PLUGIN_EXPORT int qemu_plugin_install(qemu_plugin_id_t id,
                                           const qemu_info_t *info,
                                           int argc, char **argv)
{

    for (int i = 0; i < argc; i++) {
        char *opt = argv[i];
        g_auto(GStrv) tokens = g_strsplit(opt, "=", 2);
        if (g_strcmp0(tokens[0], "mode") == 0) {
            plugin_mode = g_strdup(tokens[1]);
            if (g_strcmp0(plugin_mode, "system") != 0 && g_strcmp0(plugin_mode, "user") != 0) {
                fprintf(stderr, "Invalid mode: %s\n", plugin_mode);
                return -1;
            }
        } else if (g_strcmp0(tokens[0], "ibt") == 0) {
            if (!qemu_plugin_bool_parse(tokens[0], tokens[1], &cet_ibt_enable)) {
                fprintf(stderr, "Boolean argument parsing failed: %s\n", opt);
                return -1;
            }
        } else if (g_strcmp0(tokens[0], "ss") == 0) {
            if (!qemu_plugin_bool_parse(tokens[0], tokens[1], &cet_ss_enable)) {
                fprintf(stderr, "Boolean argument parsing failed: %s\n", opt);
                return -1;
            }
        } else if (g_strcmp0(tokens[0], "cpu_slots") == 0) {
            cpu_slots = atoi(tokens[1]);
            if (cpu_slots < MIN_CPU_SLOTS || cpu_slots > MAX_CPU_SLOTS) {
                fprintf(stderr, "Invalid CPU slots num: %d. Expectations range from %d to %d.\n", 
                    cpu_slots, MIN_CPU_SLOTS, MAX_CPU_SLOTS);
                return -1;
            }
        } else {
            fprintf(stderr, "Option parsing failed: %s\n", opt);
            return -1;
        }
    }

    qemu_plugin_outs(g_strdup_printf(LOG_PREFIX "CET plugin running...\n"));

    if(!plugin_mode)
        plugin_mode = info->system_emulation ? "system" : "user";
    qemu_plugin_outs(g_strdup_printf(LOG_PREFIX_QEMU "QEMU mode: %s\n", plugin_mode));
    if(!g_strcmp0(plugin_mode, "system")){
        qemu_plugin_outs(g_strdup_printf(LOG_PREFIX_QEMU "We dont support system mode yet!\n"));
        exit(1);
    }

    /* set up cpu numbers */
    if(IS_USER_MODE()){
        cpu_count = sysconf(_SC_NPROCESSORS_ONLN);
    } else{
        cpu_count = qemu_plugin_n_max_vcpus();
    }
    qemu_plugin_outs(g_strdup_printf(LOG_PREFIX "Physical CPU count: %u\n", cpu_count));
    qemu_plugin_outs(g_strdup_printf(LOG_PREFIX "CPU slots for CET: %u\n", cpu_slots));

    pthread_mutex_init(&cpu_lock, NULL);

    /* set up IBT/SS */
    if (IBT_ENABLED())
        if(init_cet_ibt()){
            qemu_plugin_outs(g_strdup_printf(LOG_PREFIX_IBT "Fail to initialize CET-IBT\n"));
            exit(1);
        }
    if (SS_ENABLED())
        if(init_cet_ss()){
            qemu_plugin_outs(g_strdup_printf(LOG_PREFIX_SS "Fail to initialize CET-SS\n"));
            exit(1);
        }

    /* register qemu callbacks */
#ifdef CET_HOOK_SYSCALL
    qemu_plugin_register_vcpu_syscall_cb(id, vcpu_syscall_cb);
    qemu_plugin_register_vcpu_syscall_ret_cb(id, vcpu_syscall_ret_cb);
#endif  
    qemu_plugin_register_vcpu_init_cb(id, cpu_init_cb);
    qemu_plugin_register_vcpu_exit_cb(id, cpu_exit_cb);
    qemu_plugin_register_vcpu_tb_trans_cb(id, vcpu_tb_trans);
    qemu_plugin_register_atexit_cb(id, plugin_exit_cb, NULL);
    return 0;
}
