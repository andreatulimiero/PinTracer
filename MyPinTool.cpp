#include "pin.H"
#include <stdio.h>
#include <string.h>

#define Kb 1024
#define Mb 1024 * Kb
#define Gb 1024 * Mb

#define INS_DELIMITER '\n'
#define ADDR_CHARS sizeof(ADDRINT)

#define RAW_TRACE_BUF_SIZE 512*Kb
#define TRACE_LIMIT 128*Mb
#define TRACE_NAME_LENGTH_LIMIT 128

static TLS_KEY tls_key = INVALID_TLS_KEY;
PIN_LOCK pin_lock;

static size_t spawned_threads_no;

typedef struct raw_trace_item_s {
	char* buf;
	size_t cursor_pos;
	raw_trace_item_s* next;
} raw_trace_item_t;

typedef struct raw_trace_s {
	raw_trace_item_t* head;
	raw_trace_item_t* tail;
	size_t trace_size;

	size_t threads_spawned_no;
} raw_trace_t;

bool isFirstIns = true;
const char* prog_name;

raw_trace_item_t* getNewRawTraceItem() {
	raw_trace_item_t* new_raw_trace_item = (raw_trace_item_t*)malloc(sizeof(raw_trace_item_t));
	new_raw_trace_item->buf = (char*) malloc(sizeof(char) * RAW_TRACE_BUF_SIZE);
	new_raw_trace_item->cursor_pos = 0;
	new_raw_trace_item->next = NULL;
	return new_raw_trace_item;
}

raw_trace_t* getNewRawTrace() {
	raw_trace_t* raw_trace = (raw_trace_t*)malloc(sizeof(raw_trace_t));
	raw_trace->head = getNewRawTraceItem();
	raw_trace->tail = raw_trace->head;
	raw_trace->trace_size = 0;
	raw_trace->threads_spawned_no = 0;
	return raw_trace;
}

void recordInRawTrace(const char* buf, size_t buf_len, raw_trace_t* raw_trace) {
	raw_trace_item_t* raw_trace_item = raw_trace->tail;
	//fprintf(stdout, "Cursor@%d(%d) %s\n", raw_trace_item->cursor_pos, buf_len, buf);
	//fflush(stdout);
	// If buf of latest raw_trace_item is not enough create a new one
	if (raw_trace_item->cursor_pos + buf_len >= RAW_TRACE_BUF_SIZE) {
		raw_trace_item->next = getNewRawTraceItem();
		raw_trace_item = raw_trace_item->next;
		raw_trace->tail = raw_trace_item;
	}
	memcpy(raw_trace_item->buf + raw_trace_item->cursor_pos, buf, buf_len);
	raw_trace_item->cursor_pos += buf_len;
	raw_trace->trace_size += buf_len;
}

void printRawTrace(FILE* f, raw_trace_t* raw_trace) {
	raw_trace_item_t* rti = raw_trace->head;
	while (rti != NULL) {
		for (size_t i = 0; i < rti->cursor_pos; i++) {
			fputc(rti->buf[i], f);
		}
		rti = rti->next;
	}
}

void INS_Analysis(char* disassembled_ins, UINT32 disassembled_ins_len, THREADID thread_idx) {
	raw_trace_t* raw_trace = (raw_trace_t*) PIN_GetThreadData(tls_key, thread_idx);
	if (raw_trace->trace_size >= TRACE_LIMIT) return;
	recordInRawTrace(disassembled_ins, disassembled_ins_len, raw_trace);
}

void INS_JumpAnalysis(ADDRINT target_branch, INT32 taken, THREADID thread_idx) {
	if (!taken) return;
	raw_trace_t* raw_trace = (raw_trace_t*)PIN_GetThreadData(tls_key, thread_idx);
    /* Allocate enough space in order to save:
            - @ char (1 byte)
            - address in hex format (sizeof(ADDRINT) * 2 bytes) + '0x' prefix (2 bytes)
            - \n delimiter (1 byte)
			- 0 terminator (1 byte)
    */
    size_t buf_len = (sizeof(ADDRINT) * 2 + 5);
    char *buf = (char*) calloc(1, sizeof(char) * buf_len);
    buf[0] = '\n';
    buf[1] = '@';
    sprintf(buf + 2, "%x", target_branch);
    recordInRawTrace(buf, buf_len, raw_trace);
}

void Trace(TRACE trace, void* v) {
	// Let's whitelist the instrumented program only
	RTN rtn = TRACE_Rtn(trace);
	if (RTN_Valid(rtn)) {
		SEC sec = RTN_Sec(rtn);
		if (SEC_Valid(sec)) {
			IMG img = SEC_Img(sec);
			if (IMG_Valid(img)) {
				if (!strstr(IMG_Name(img).c_str(), prog_name)) {
					//fprintf(stdout, "[-] Ignoring %s\n", IMG_Name(img).c_str());
					return;
				}
				//fprintf(stdout, "[+] Instrumenting %s <= %s\n", IMG_Name(img).c_str(), prog_name);
				//fflush(stdout);
			} else return;
		} else return;
	} else return;

    for (BBL bbl = TRACE_BblHead(trace); BBL_Valid(bbl); bbl = BBL_Next(bbl)) {
		for (INS ins = BBL_InsHead(bbl); INS_Valid(ins); ins = INS_Next(ins)) {
			string disassembled_ins_s = INS_Disassemble(ins);
			/* Allocate enough space to save
				- Disassembled instruction (n bytes)
				- INS_DELIMITER (1 byte)
				- 0 terminator (1 byte)
			*/
			uint32_t disassembled_ins_len = strlen(disassembled_ins_s.c_str()) + 2;
			char* disassembled_ins = (char*) calloc(1, sizeof(char) * (disassembled_ins_len));
			disassembled_ins[0] = INS_DELIMITER;
			strcpy(disassembled_ins + 1, disassembled_ins_s.c_str());
			if (isFirstIns) {
				isFirstIns = false;
				strcpy(disassembled_ins, disassembled_ins + 1);
			}

			INS_InsertCall(ins, IPOINT_BEFORE, 
				(AFUNPTR)INS_Analysis,
				IARG_PTR,
				disassembled_ins,	
				IARG_UINT32,
				disassembled_ins_len,
				IARG_THREAD_ID,
				IARG_END);
			

			if (INS_IsBranchOrCall(ins)) {
				INS_InsertCall(ins, IPOINT_BEFORE,
					(AFUNPTR)INS_JumpAnalysis,
					IARG_BRANCH_TARGET_ADDR,
					IARG_BRANCH_TAKEN,
					IARG_THREAD_ID,
					IARG_END);
			}
		}
    }
}

void ThreadStart(THREADID thread_idx, CONTEXT* ctx, INT32 flags, VOID* v) {
	fprintf(stdout, "[*] Spawned thread %d\n", thread_idx);
	fflush(stdout);
	/* Initialize a raw trace per thread */
	PIN_GetLock(&pin_lock, thread_idx);
	spawned_threads_no++;
	if (PIN_SetThreadData(tls_key, getNewRawTrace(), thread_idx) == FALSE) {
		fprintf(stderr, "[x] PIN_SetThreadData failed");
		PIN_ExitProcess(1);
	}
	PIN_ReleaseLock(&pin_lock);

}

void ThreadFini(THREADID thread_idx, const CONTEXT* ctx, INT32 code, VOID* v) {
	fprintf(stdout, "[*] Finished thread %d\n", thread_idx);
	fflush(stdout);
	char filename[TRACE_NAME_LENGTH_LIMIT] = { 0 };
	sprintf(filename, "trace_%d.out", thread_idx);
	FILE* out = fopen(filename, "w+");
	raw_trace_t* raw_trace = (raw_trace_t*)PIN_GetThreadData(tls_key, thread_idx);
	printRawTrace(out, raw_trace);
	fprintf(stdout, "[+] Saved to %s\n", filename);
}

void Fini(INT32 code, VOID *v) {
	fprintf(stdout, "=======================\n");
	fprintf(stdout, "Trace finished\n");
	//fprintf(stdout, "Size: %d Kb\n", raw_trace->trace_size / (1024));
	fprintf(stdout, "Threads spawned: %d\n", spawned_threads_no);
	fprintf(stdout, "=======================\n");
}

int main(int argc, char *argv[]) {
	/* Init PIN */
	if (PIN_Init(argc, argv)) {
		fprintf(stderr, "[x] An error occured while initiating PIN\n");
		return 0;
	}
	
	/* Prepare TLS */
	tls_key = PIN_CreateThreadDataKey(NULL);
	if (tls_key == INVALID_TLS_KEY) {
		fprintf(stderr, "[x] Number of already allocated keys reached the MAX_CLIENT_TLS_KEYS limit\n");
		PIN_ExitProcess(1);
	}

	/* Prepare Lock */
	PIN_InitLock(&pin_lock);
		
	prog_name = argv[argc - 1];
    TRACE_AddInstrumentFunction(Trace, 0);

	PIN_AddThreadStartFunction(ThreadStart, 0);
	PIN_AddThreadFiniFunction(ThreadFini, 0);
    
	PIN_AddFiniFunction(Fini, 0);
    PIN_StartProgram();
    return 0;
}
