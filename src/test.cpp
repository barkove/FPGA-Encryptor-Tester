#include <QCoreApplication>
#include <string.h>
#include "gost.h"
#include <QFile>
#include <QDateTime>
#include <QTextStream>
#include <qDebug>

#define FILENAME_LENGTH 40
#define MY_RAND_A 6364136223846793005llu
#define MY_RAND_C 1442695040888963407llu

uint8_t Gost_Table[_GOST_TABLE_SIZE] = {
    0x0C, 0x04, 0x06, 0x02, 0x0A, 0x05, 0x0B, 0x09, 0x0E, 0x08, 0x0D, 0x07, 0x00, 0x03, 0x0F, 0x01,
    0x06, 0x08, 0x02, 0x03, 0x09, 0x0A, 0x05, 0x0C, 0x01, 0x0E, 0x04, 0x07, 0x0B, 0x0D, 0x00, 0x0F,
    0x0B, 0x03, 0x05, 0x08, 0x02, 0x0F, 0x0A, 0x0D, 0x0E, 0x01, 0x07, 0x04, 0x0C, 0x09, 0x06, 0x00,
    0x0C, 0x08, 0x02, 0x01, 0x0D, 0x04, 0x0F, 0x06, 0x07, 0x00, 0x0A, 0x05, 0x03, 0x0E, 0x09, 0x0B,
    0x07, 0x0F, 0x05, 0x0A, 0x08, 0x01, 0x06, 0x0D, 0x00, 0x09, 0x03, 0x0E, 0x0B, 0x04, 0x02, 0x0C,
    0x05, 0x0D, 0x0F, 0x06, 0x09, 0x02, 0x0C, 0x0A, 0x0B, 0x07, 0x08, 0x01, 0x04, 0x03, 0x0E, 0x00,
    0x08, 0x0E, 0x02, 0x05, 0x06, 0x09, 0x01, 0x0C, 0x0F, 0x04, 0x0B, 0x00, 0x0D, 0x0A, 0x03, 0x07,
    0x01, 0x07, 0x0E, 0x0D, 0x00, 0x05, 0x08, 0x03, 0x04, 0x0F, 0x0A, 0x06, 0x09, 0x0C, 0x0B, 0x02
};
uint8_t GOST_Key_d[_GOST_Key_Size] = {
        0x69, 0x96, 0x96, 0x69, 0x96, 0x69, 0x69, 0x96, 0x96, 0x69, 0x69, 0x96, 0x69, 0x96, 0x96, 0x69,
        0x96, 0x69, 0x69, 0x96, 0x69, 0x96, 0x96, 0x69, 0x69, 0x96, 0x96, 0x69, 0x96, 0x69, 0x69, 0x96,
};

/*
uint8_t Data_O[24] = {
    0x6A, 0xDB, 0x6E, 0xC5, 0x3E, 0xC6, 0x45, 0xA4, 0x70, 0xA8, 0x22, 0xB8, 0x94, 0xA7, 0xFE, 0x28,
    0x38, 0x48, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};
//Data from real etalon cryptor:
//imitta
uint8_t Imitta_Et[_GOST_Imitta_Size] ={
        0xD9, 0x8F, 0xEB, 0x04, 0x81, 0xF6, 0x2C, 0x41
};
#if _GOST_ROT_Synchro_GAMMA==1
//synchro
uint8_t Synchro_Et[_GOST_Synchro_Size] =
{
    0xC3, 0xA7,0x80, 0x2A, 0x47, 0xE3, 0xA8, 0xFF
};
#else
uint8_t Synchro_Et[_GOST_Synchro_Size] =
{
   0x47, 0xE3, 0xA8, 0xFF, 0xC3, 0xA7,0x80, 0x2A
};
#endif
//Simple replacement
uint8_t Data_C_S_Et[24] = {
    0x12, 0xA2, 0x8E, 0x60, 0x5D, 0x76, 0xBF, 0xC9, 0xAF, 0x84, 0x67, 0x8A, 0xA5, 0xE8, 0xF7, 0xE8,
    0xDE, 0x8E, 0x29, 0x16, 0x19, 0xCB, 0xD2, 0x08
};
//Gamma
unsigned char Data_C_G_Et[24] = {
    0x8B, 0x39, 0x76, 0x8B, 0x52, 0xE3, 0x94, 0x1D, 0xEA, 0x22, 0xC7, 0x24, 0x86, 0x56, 0xA2, 0xCE,
    0x11, 0x61, 0xF0, 0x07, 0x4B, 0xF8, 0xCA, 0x00
};
//Gamma with feedback
unsigned char Data_C_GF_Et[24] = {
    0x20, 0x36, 0xB4, 0x76, 0x29, 0x44, 0x36, 0xDE, 0xF1, 0x17, 0x0F, 0x02, 0x82, 0x40, 0x00, 0x05,
    0xEC, 0x04, 0x87, 0xBB, 0xF4, 0x46, 0x0A, 0xA2
};
*/

uint64_t my_srand;

void my_rand_init()
{
    my_srand = QDateTime::currentMSecsSinceEpoch();
}

uint64_t my_rand()
{
    static uint64_t last_value = my_srand;
    uint64_t result   = 0;
    last_value        = (MY_RAND_A * last_value + MY_RAND_C) % (~0);
    result            = last_value & 0xFFFFFFFF00000000;
    last_value        = (MY_RAND_A * last_value + MY_RAND_C) % (~0);
    result           |= (last_value & 0xFFFFFFFF00000000) >> 32;
    return last_value;
}

void random_init()
{
    qsrand(QDateTime::currentMSecsSinceEpoch());
}

void random_block(GOST_Data_Part *ptr)
{
    ptr->full = 0;
    uint64_t test;
    for (int i = 0; i < 8 * sizeof(GOST_Data_Part); ++i) {
        test = (1 << i) * (qrand() % 2);
        ptr->full |= test;
    }
}

void cleaner()
{
    char c;
    while ((c = getchar()) != '\n');
}

void fprint_block(FILE *fptr, GOST_Data_Part *ptr)
{
    fprintf(fptr, "%016llx\r\n", ptr->full);
}

int main(int argc, char *argv[])
{
    for (;;) {
        char mode;
        printf("Enter the mode of generation\r\n"
               "1 - One stage of simple replacement\r\n"
               "2 - Simple replacement mode\r\n");
        if ( ( (mode = getchar()) != '1' ) && ( mode != '2' ) ) {
            printf("Mode has not been entered\r\n");
            cleaner();
            continue;
        }
        cleaner();

        char filename[FILENAME_LENGTH - 8];
        printf("Enter the file name of input values file that will be generated\r\n(example - test "
               "(test_enc.txt will be created automatically), size of name < %d symbols)\r\n", FILENAME_LENGTH - 8  );
        scanf("%s", filename);
        filename[FILENAME_LENGTH - 8 - 1] = '\0';
        cleaner();

        uint64_t quantity;
        printf("Enter the quantity of test values that will be generated\r\n");
        if (scanf("%lld", &quantity) != 1) {
            printf("Quantity has not been entered\r\n");\
            cleaner();
            continue;
        }
        cleaner();

        printf("Do you want to enter the key (in this case default (or last) key will be lost)? (Y / <another symbol>)\r\n");
        char key_in = getchar();
        cleaner();
        if (key_in == 'Y') {
            for (int i = 0; i < sizeof(GOST_Key_d) / 4; ++i) {
                printf("Enter the number that corresponding to "
                       "digit places %d - %d of key (hexadecimal number)\r\n", 32 * (i + 1) - 1, 32 * i);
                if (scanf("%x", ((uint32_t *) GOST_Key_d) + i) != 1) {
                    printf("You have entered incorrect number\r\n");
                    cleaner();
                    --i;
                    continue;
                }
                cleaner();
            }
            printf("My input for key:\r\n");
            for (int i = 0; i < sizeof(GOST_Key_d) / 4; ++i)
                printf("%d value: %08x\r\n", i + 1, *(((uint32_t *) GOST_Key_d) + i) );
        }

        GOST_Data_Part block;
        //random_init();
        my_rand_init();

        FILE *InValues, *OutValues;

        char filename_in  [FILENAME_LENGTH];
        char filename_out [FILENAME_LENGTH];

        strcpy(filename_in,  filename  );
        strcat(filename_in,  ".txt"    );
        strcpy(filename_out, filename  );
        strcat(filename_out, "_enc.txt");

        if ( ( InValues  = fopen(filename_in , "w") ) &&
             ( OutValues = fopen(filename_out, "w") )    ) {

            for (uint64_t i = 0; i < quantity; ++i) {
                //random_block(&block);
                block.full = my_rand();
                fprint_block(InValues, &block);

                if (mode == '2') {
                    GOST_Encrypt_SR(block.parts, sizeof(GOST_Data_Part), true, Gost_Table, GOST_Key_d);
                }
                else if (mode == '1') {
                    GOST_Crypt_Step(&block, Gost_Table, *((uint32_t *) GOST_Key_d), 0);
                }

                fprint_block(OutValues, &block);
            }

            bool err = fclose(InValues) || fclose(OutValues);
            if (!err) {
                printf("Files have been created\r\n");
            }
            else {
                printf("The error has been occured\r\n");
            }
        }
        else {
            printf("Files haven't been created\r\n");
        }

        char choose;
        printf("Do you wish to complete this program? (Y / <another symbol>)\r\n");
        if ((choose = getchar()) == 'Y')
            break;
        cleaner();
    }
    return 0;
}

/*
uint8_t  Imitta[_GOST_Imitta_Size];
uint8_t  Data_E[sizeof(Data_O)];
uint8_t  Synchro[_GOST_Synchro_Size];
int main(int argc, char *argv[])
{
    QCoreApplication a(argc, argv);
//Imitta test
    memset(Imitta,_GOST_Def_Byte,_GOST_Imitta_Size);
    GOST_Imitta(Data_O, Imitta, sizeof(Data_O),Gost_Table,GOST_Key_d);
    if (memcmp(Imitta,Imitta_Et,_GOST_Imitta_Size))
    {
        printf("Imitta test failed\r\n");
    } else
    {
        printf("Imitta test passed\r\n");
    }
//Simple replacement
    memcpy(Data_E,Data_O,sizeof(Data_O));
    GOST_Encrypt_SR(Data_E,sizeof(Data_E),_GOST_Mode_Encrypt,Gost_Table,GOST_Key_d);
    if (memcmp(Data_C_S_Et,Data_E,sizeof(Data_E)))
    {
        printf("Simple replacement encryption test failed\r\n");
    } else
    {
        printf("Simple replacement encryption test passed\r\n");
    }
    GOST_Encrypt_SR(Data_E,sizeof(Data_E),_GOST_Mode_Decrypt,Gost_Table,GOST_Key_d);
    if (memcmp(Data_O,Data_E,sizeof(Data_E)))
    {
        printf("Simple replacement decryption test failed\r\n");
    } else
    {
        printf("Simple decryption test passed\r\n");
    }
//Gamma
    memcpy(Data_E,Data_O,sizeof(Data_O));
    memcpy(Synchro,Synchro_Et,sizeof(Synchro));
    GOST_Crypt_G_PS(Synchro,Gost_Table,GOST_Key_d);//Decrypt Synchro acording to standart
    GOST_Crypt_G_Data(Data_E,sizeof(Data_E),Synchro,Gost_Table,GOST_Key_d);
    if (memcmp(Data_E,Data_C_G_Et,sizeof(Data_E)))
    {
        printf("Gamma encryption test failed\r\n");
    } else
    {
        printf("Gamma encryption test passed\r\n");
    }

    memcpy(Synchro,Synchro_Et,sizeof(Synchro));
    GOST_Crypt_G_PS(Synchro,Gost_Table,GOST_Key_d);//Decrypt Synchro acording to standart
    GOST_Crypt_G_Data(Data_E,sizeof(Data_E),Synchro,Gost_Table,GOST_Key_d);
    if (memcmp(Data_O,Data_E,sizeof(Data_E)))
    {
        printf("Gamma decryption test failed\r\n");
    } else
    {
        printf("Gamma decryption test passed\r\n");
    }
//Gamma with feedback
    memcpy(Synchro,Synchro_Et,sizeof(Synchro));
    memcpy(Data_E,Data_O,sizeof(Data_O));
#if _GOST_ROT_Synchro_GAMMA==1
    GOST_Crypt_GF_Prepare_S(Synchro);
#endif
    GOST_Crypt_GF_Data(Data_E,sizeof(Data_E),Synchro,_GOST_Mode_Encrypt,Gost_Table,GOST_Key_d);
    if (memcmp(Data_E,Data_C_GF_Et,sizeof(Data_E)))
    {
        printf("Gamma with feedback encryption test failed\r\n");
    } else
    {
       printf("Gamma with feedback encryption test passed\r\n");
    }
    memcpy(Synchro,Synchro_Et,sizeof(Synchro));
#if _GOST_ROT_Synchro_GAMMA==1
    GOST_Crypt_GF_Prepare_S(Synchro);
#endif
    GOST_Crypt_GF_Data(Data_E,sizeof(Data_E),Synchro,_GOST_Mode_Decrypt,Gost_Table,GOST_Key_d);
    if (memcmp(Data_O,Data_E,sizeof(Data_E)))
    {
        printf("Gamma with feedback decryption test failed\r\n");
    } else
    {
       printf("Gamma with feedback decryption test passed\r\n");
    }
    return 0;
}

*/
