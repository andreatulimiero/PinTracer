#include "pin.H"
#include <stdio.h>
#include <string.h>

#define Kb 1024
#define Mb 1024 * Kb
#define Gb 1024 * Mb

#define RAW_TRACE_BUF_SIZE 512*Kb
#define TRACE_LIMIT 1*Gb
#define INS_DELIMITER '\n'

typedef struct raw_trace_item_s {
	char* buf;
	size_t cursor_pos;
	raw_trace_item_s* next;
} raw_trace_item_t;

typedef struct raw_trace_s {
	raw_trace_item_t* head;
	raw_trace_item_t* tail;
	size_t trace_size;
} raw_trace_t;

raw_trace_t* raw_trace;
bool isFirstIns = true;

const char* prog_name;

raw_trace_item_t* getNewRawTraceItem() {
	raw_trace_item_t* new_raw_trace_item = (raw_trace_item_t*)malloc(sizeof(raw_trace_item_t));
	new_raw_trace_item->buf = (char*)malloc(sizeof(char) * RAW_TRACE_BUF_SIZE);
	new_raw_trace_item->cursor_pos = 0;
	new_raw_trace_item->next = NULL;
	return new_raw_trace_item;
}

void printRawTrace(FILE* f) {
	raw_trace_item_t* rti = raw_trace->head;
	while (rti != NULL) {
		for (size_t i = 0; i < rti->cursor_pos; i++) {
			fputc(rti->buf[i], f);
		}
		rti = rti->next;
	}
}

void INS_Analysis(char* disassembled_ins, UINT32 disassembled_ins_len) {
	if (raw_trace->trace_size >= TRACE_LIMIT) return;
	raw_trace_item_t* raw_trace_item = raw_trace->tail;
	// printf("Cursor@%d(%d) %s\n", raw_trace_item->cursor_pos, disassembled_ins_len, disassembled_ins);
	// If buf of latest raw_trace_item is not enough create a new one
	if (raw_trace_item->cursor_pos + disassembled_ins_len >= RAW_TRACE_BUF_SIZE) {
		raw_trace_item->next = getNewRawTraceItem();
		raw_trace_item = raw_trace_item->next;
		raw_trace->tail = raw_trace_item;
	}
	memcpy(raw_trace_item->buf + raw_trace_item->cursor_pos, disassembled_ins, disassembled_ins_len);
	raw_trace_item->cursor_pos += disassembled_ins_len;
	raw_trace->trace_size += disassembled_ins_len;
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
					return;
				}
			} else return;
		} else return;
	} else return;

    for (BBL bbl = TRACE_BblHead(trace); BBL_Valid(bbl); bbl = BBL_Next(bbl)) {
		for (INS ins = BBL_InsHead(bbl); INS_Valid(ins); ins = INS_Next(ins)) {
			string disassembled_ins_s = INS_Disassemble(ins);
			uint32_t disassembled_ins_len = disassembled_ins_s.length() + 1;
			char* disassembled_ins = (char*) calloc(1, sizeof(char) * (disassembled_ins_len ));
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
				IARG_END);
		}
    }
}

void Fini(INT32 code, VOID *v) {
	FILE* out = fopen("trace.out", "w+");
	printRawTrace(out);
}

int main(int argc, char *argv[]) {
	PIN_Init(argc, argv);

	prog_name = argv[argc - 1];

	raw_trace = (raw_trace_t*) malloc(sizeof(raw_trace_t));
	raw_trace->head = getNewRawTraceItem();
	raw_trace->tail = raw_trace->head;

    TRACE_AddInstrumentFunction(Trace, 0);
    PIN_AddFiniFunction(Fini, 0);
    PIN_StartProgram();
    return 0;
}
