
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../target/dash_spv_masternode_processor.h"


typedef union _UInt256 {
    uint8_t u8[256 / 8];
    uint16_t u16[256 / 16];
    uint32_t u32[256 / 32];
    uint64_t u64[256 / 64];
} UInt256;

uint32_t getBlockHeightByHash(uint8_t (*block_hash)[32], const void *context) {
    //DSMasternodeProcessorContext *processorContext = (__bridge DSMasternodeProcessorContext *)context;
    //uint32_t block_height = context.blockHeightLookup(block_hash);
    printf("getBlockHeightByHash: \n");
    printf("%p\n", block_hash);
    printf("%p\n", context);
    //mndiff_block_hash_destroy(block_hash);
    //return block_height;
    return 0;
}

void destroyHash(uint8_t* block_hash) {
    //NSLog(@"destroyHash: %p", block_hash);
    //NSLog(@"destroyHash: %p", block_hash);
     printf("destroyHash: \n");
     printf("%p\n", block_hash);
   free(block_hash);
}


uint8_t *getMerkleRootByHash(uint8_t (*block_hash)[32], const void *context) {
    UInt256 blockHash = *((UInt256 *)block_hash);
    printf("getMerkleRootByHash: %p\n", &blockHash);
    uint8_t (*merkle_root)[32] = malloc(32); \
    printf("getMerkleRootByHash: %p\n", &merkle_root);
    memcpy(merkle_root, (const void *) "00000000000000000000000000000000", 32); \
    printf("getMerkleRootByHash: %p\n", &merkle_root);
    processor_destroy_block_hash(block_hash);
    printf("getMerkleRootByHash: %p\n", &merkle_root);
    return (const uint8_t *)merkle_root;
}

struct Ctx {
    const char *chain;
};


char* readQRInfo() {
    FILE *f = fopen("files/QRINFO_1_17800.dat", "rb");
    fseek(f, 0, SEEK_END);
    long fsize = ftell(f);
    fseek(f, 0, SEEK_SET);  /* same as rewind(f); */

    char *string = malloc(fsize + 1);
    fread(string, fsize, 1, f);
    fclose(f);
    string[fsize] = 0;
    return string;
}



int main (void) {
    char *proof_hex = "01761149f5816723fdc7025790d285f63bbe26acb3471e57f28fa4db6e4859c3ae02887fcd3a7fef9b356dd12fc2e4d58c54c9e42908070dee2aaf7c7b5d389f736010017d1db154d2a87f5f5136a1b8581759b75e72d6047ee3efbfcba0889c2d4e8b6302b1a68c50747a42fd140dedcabb7c4ff3ebed1c729a1541ba1b44f1ad7c24a3e21003206c05f39cee3a2c1436b61a0746503a743658b2d0e76b432e741f9bbbe211dc34008001000000a462696458206c05f39cee3a2c1436b61a0746503a743658b2d0e76b432e741f9bbbe211dc346762616c616e63651a3b9ac7f4687265766973696f6e006a7075626c69634b65797381a36269640064646174615821032d6d975393f17c0d605efe8562c06cbfc913afcc73d0d855399c0a97d776154064747970650002163fc42a48f26886519b6e64280729c5246d92dad847823faef877eb282c7fb81001d715565e9f71ae94fe2d07568d1e2fd1043bca07c2da385dcb430cb84f92882211022325a14555b8403767a314c3bc9b8708a25e2bc756cecadf56e5184de8dcc3a31001b51e23fbb805bfd917bb0e131da4488c48417dbe82bd6d7e9d69a50abd77a3c31102f41f6cae67288cccacc79ab5c2c29fd6ec3b83919625131ec9139c65606849c61001f234e77a4845b865816729fa14801189395d2ce658c1a24130f45b076d8f047a11111102c97ff70a287f4d9741f5c54e5fc5e6a365043cdbedf623ae7d0e280a6a32b70b10018a28f5bebdbf987079878315cde74e22ef591983a576d3c6e2807ae1fd12ff8811";
    struct Ctx context = (struct Ctx){.chain = proof_hex};
    test_func(getMerkleRootByHash, destroyHash, &context);
}

void test_qrinfo_from_message() {
    char *proof_hex = "01761149f5816723fdc7025790d285f63bbe26acb3471e57f28fa4db6e4859c3ae02887fcd3a7fef9b356dd12fc2e4d58c54c9e42908070dee2aaf7c7b5d389f736010017d1db154d2a87f5f5136a1b8581759b75e72d6047ee3efbfcba0889c2d4e8b6302b1a68c50747a42fd140dedcabb7c4ff3ebed1c729a1541ba1b44f1ad7c24a3e21003206c05f39cee3a2c1436b61a0746503a743658b2d0e76b432e741f9bbbe211dc34008001000000a462696458206c05f39cee3a2c1436b61a0746503a743658b2d0e76b432e741f9bbbe211dc346762616c616e63651a3b9ac7f4687265766973696f6e006a7075626c69634b65797381a36269640064646174615821032d6d975393f17c0d605efe8562c06cbfc913afcc73d0d855399c0a97d776154064747970650002163fc42a48f26886519b6e64280729c5246d92dad847823faef877eb282c7fb81001d715565e9f71ae94fe2d07568d1e2fd1043bca07c2da385dcb430cb84f92882211022325a14555b8403767a314c3bc9b8708a25e2bc756cecadf56e5184de8dcc3a31001b51e23fbb805bfd917bb0e131da4488c48417dbe82bd6d7e9d69a50abd77a3c31102f41f6cae67288cccacc79ab5c2c29fd6ec3b83919625131ec9139c65606849c61001f234e77a4845b865816729fa14801189395d2ce658c1a24130f45b076d8f047a11111102c97ff70a287f4d9741f5c54e5fc5e6a365043cdbedf623ae7d0e280a6a32b70b10018a28f5bebdbf987079878315cde74e22ef591983a576d3c6e2807ae1fd12ff8811";
    //&mut (FFIContext { chain }) as *mut _ as *mut std::ffi::c_void
    struct Ctx context = (struct Ctx){.chain = proof_hex};
    struct MasternodeManager *processor = register_processor(
    getBlockHeightByHash, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL);

    printf("--------------\n register_processor \n--------------\n");
    printf("%p\n", processor);
//    printf("%p\n", processor->context);
    printf("\n");


    FILE *fileptr;
    char *buffer;
    long filelen;
    fileptr = fopen("files/QRINFO_1_17800.dat", "rb");  // Open the file in binary mode
    fseek(fileptr, 0, SEEK_END);          // Jump to the end of the file
    filelen = ftell(fileptr);             // Get the current byte offset in the file
    rewind(fileptr);                      // Jump back to the beginning of the file
    buffer = (char *)malloc(filelen * sizeof(char)); // Enough memory for the file
    fread(buffer, filelen, 1, fileptr); // Read in the entire file
    fclose(fileptr); // Close the file

    struct LLMQRotationInfoResult *result = process_qrinfo_from_message(buffer, filelen, 0, 0, true, 0, processor);
    printf("--------------\n process \n--------------\n");
    printf("%p\n", result);
    printf("\n");
}


// clang c/main.c target/universal/release/libdash_spv_masternode_processor_macos.a -o test && ./test
