#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>

typedef unsigned char u8;
typedef unsigned short u16;
typedef unsigned int u32;

typedef struct
{
	u8 ident[16];  // struct definition for ELF object header
	u16 type;
	u16 machine;
	u32 version;
	u32 entry;
	u32 phoff;
	u32 shoff;
	u32 flags;
	u16 ehsize;
	u16 phentsize;
	u16 phnum;
	u16 shentsize;
	u16 shnum;
	u16 shstrndx;
} elf_header_t;

typedef struct
{
     u32   sh_name;
     u32   sh_type;
     u32   sh_flags;
     u32 sh_addr;
     u32   sh_offset;
     u32   sh_size;
     u32   sh_link;
     u32   sh_info;
     u32   sh_addralign;
     u32   sh_entsize;
} section_header_t;

typedef struct
{
    u8 magic[4];
    u32 segments;
    u32 entry;
    u32 text_size;
    u32 data_size;
    u32 bss_size;
    u32 load_cb_start;
    u32 load_cb_end;
    u8 fname[32];
    u8 padding[64];
} overlay_header_t;

typedef struct
{
    u8* data;
    u32 size;
} section_t;


char *conv_extension(char* myStr, bool pal) {
    char *retStr;
    char *lastExt;
    if (myStr == NULL) return NULL;
    if ((retStr = malloc (strlen (myStr) + 1)) == NULL) return NULL;
    strcpy (retStr, myStr);
    lastExt = strrchr (retStr, '.');
    if (lastExt != NULL) {
        *(lastExt+1) = (pal ? 'p' : 'n');
        *(lastExt+2) = 'm';
        *(lastExt+3) = '\0';
    }

    return retStr;
}

int main(int argc, char *argv[]) {
    elf_header_t elf_header;
    section_header_t shstr_header;
    overlay_header_t overlay_header;
    section_t text, data, bss;
    text.size = 0;
    data.size = 0;
    bss.size = 0;
    
    bool export_bss = true, pal = false;
    char* section_names;
    char* new_fname = NULL;
    u8 sections_wrote = 0;
    bool has_text = false, has_data = false, has_bss = false;
    u32 entry = 0;
    FILE* fp, *out;

    if (argc > 1) {
        printf("PlayStation 2 ELF to MetroWerks overlay converter - Created by Daniel Santos\n");
        printf("File: %s\n\n", argv[1]);

        for(int i = 2; i < argc; i++) {
            if (strcmp("-nobss", argv[i]) == 0) {
                printf(".bss section export disabled\n");
                export_bss = false;
            } else if (strcmp("-pal", argv[i]) == 0) {
                printf("Changed overlay file region to PAL\n");
                pal = true;
            } else if (strstr(argv[i], "-entry=") != NULL) {
                entry = (u32)strtol(&argv[i][7], NULL, 0);
            }
        }

        fp = fopen(argv[1], "rb");
        fread(&elf_header, sizeof(elf_header_t), 1, fp);

        fseek(fp, elf_header.shoff + elf_header.shstrndx * sizeof(section_header_t), SEEK_SET);
        fread(&shstr_header, sizeof(section_header_t), 1, fp);

        section_names = malloc(shstr_header.sh_size);
        fseek(fp, shstr_header.sh_offset, SEEK_SET);
        fread(section_names, shstr_header.sh_size, 1, fp);

        section_header_t* section_header = (section_header_t*)malloc(sizeof(section_header_t)*elf_header.shnum);

        fseek(fp, elf_header.shoff, SEEK_SET);
        fread(section_header, sizeof(section_header_t)*elf_header.shnum, 1, fp);

        for(int j = 0; j < elf_header.shnum; j++){
            has_text = strcmp(section_names + section_header[j].sh_name, ".text") == 0;
            has_data = strcmp(section_names + section_header[j].sh_name, ".data") == 0;
            has_bss = strcmp(section_names + section_header[j].sh_name, ".bss") == 0;

            if ( has_text || has_data || (has_bss && export_bss) ) {
                if (has_text) {
                    text.size = section_header[j].sh_size;
                    text.data = malloc(section_header[j].sh_size);
                    fseek(fp, section_header[j].sh_offset, SEEK_SET);
                    fread(text.data, text.size, 1, fp);
                } else if (has_data) {
                    data.size = section_header[j].sh_size;
                    data.data = malloc(section_header[j].sh_size);
                    fseek(fp, section_header[j].sh_offset, SEEK_SET);
                    fread(data.data, data.size, 1, fp);
                } else {
                    bss.size = section_header[j].sh_size;
                    bss.data = malloc(section_header[j].sh_size);
                    fseek(fp, section_header[j].sh_offset, SEEK_SET);
                    fread(bss.data, bss.size, 1, fp);
                }

                printf("%s section - address: 0x%x | offset: 0x%x | size: %d\n", section_names + section_header[j].sh_name, section_header[j].sh_addr, section_header[j].sh_offset, section_header[j].sh_size);
                sections_wrote++;
            }
        }

        if(sections_wrote > 0) {
            strcpy(overlay_header.magic, "MWo3");
            overlay_header.segments = sections_wrote+1;
            overlay_header.entry = entry;
            new_fname = conv_extension(argv[1], pal);
            out = fopen(new_fname, "wb");

            memset(overlay_header.fname, 0, 32);
            if (strlen(new_fname) <= 32) {
                strcpy(overlay_header.fname, new_fname);
            } else {
                printf("File name size must be smaller than 32 characters\n");
            }

            overlay_header.text_size = text.size;
            overlay_header.data_size = data.size;
            overlay_header.bss_size = bss.size;

            memset(overlay_header.padding, 0, 64);

            fwrite(&overlay_header, sizeof(overlay_header_t), 1, out);

            if(text.size > 0) 
                fwrite(text.data, text.size, 1, out);
            if(data.size > 0) 
                fwrite(data.data, data.size, 1, out);
            if(bss.size > 0) 
                fwrite(bss.data, bss.size, 1, out);

            fclose(out);
        }

        free(section_names);
        free(section_header);

        fclose(fp);
    }
    
}