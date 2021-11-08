
#include< ntifs.h>
#include <ntddk.h>
#include <ntstrsafe.h>
#include < mbstring.h >


#include <wchar.h>
#define LINK_NAME	L"\\DosDevices\\catholic"
#define MAX 512
#define ALLOC_MAX 300
#define DEVICE_NAME L"\\Device\\test"


#define IOCTL_INIT  CTL_CODE(FILE_DEVICE_UNKNOWN,0x4000,METHOD_BUFFERED,FILE_ANY_ACCESS)  //0x230000
#define IOCTL_ADD   0x230111
#define IOCTL_DEL   0x230222

/*
#define IOCTL_ADD  CTL_CODE(FILE_DEVICE_UNKNOWN,0x230111,METHOD_BUFFERED,FILE_ANY_ACCESS)  
#define IOCTL_DEL  CTL_CODE(FILE_DEVICE_UNKNOWN,0x230222,METHOD_BUFFERED,FILE_ANY_ACCESS)  
#define IOCTL_INIT  CTL_CODE(FILE_DEVICE_UNKNOWN,0x4000,METHOD_BUFFERED,FILE_ANY_ACCESS) 
*/
#define _NO_CRT_STDIO_INLINE //추가
#pragma comment(lib,"ucrt.lib")
#define NTSTRSAFE_LIB
OBJECT_ATTRIBUTES oa;
PDEVICE_OBJECT MyDevice;
UNICODE_STRING DeviceLink;
UNICODE_STRING DeviceName;
UNICODE_STRING uFilename;
HANDLE hFile = NULL;
IO_STATUS_BLOCK iostatus;
PCHAR psList[10];
int psCnt;
WCHAR g_TempString[512] = { 0, }; // 메모리할당을 하는것이 좋지만, 지금 수준에서는 전역변수를 사용합니다
WCHAR a_tmpString[512] = { 0, };


INT processCount(CHAR arr[], INT len) {
    int k = 0;
    psCnt = 0;
    for (int i = 0; i < len; i++)
        if (i > 3
            && arr[i] == 'e'
            && arr[i - 1] == 'x'
            && arr[i - 2] == 'e')
            psCnt++;

    k = psCnt;
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, 0, "[*]0000  PSCOUNT !--------: %d\n", psCnt);
    return k;
}
VOID StringParse(PCHAR arr,ULONG txtLen) {

    int  point = 0,i = 0;
    NTSTATUS status;
    for (int k = 0; k < psCnt; k++) {
        
        for (int  i = 0 ; arr[i] !='\n'; i++) {
           // DbgPrintEx(DPFLTR_IHVDRIVER_ID, 0, "[*] TXT CHAR is %c \n", arr[i]);
            if (i > 3 &&  arr[i] == 'e' &&  arr[i-1]=='x' && arr[i-2] == 'e') {
                //notepad.exe\r\n -> i가 10일때 마지막 e로온다. 하지만 길이는 11
                
                i++; // \r을 가리킨다.
                
                DbgPrintEx(DPFLTR_IHVDRIVER_ID, 0, "[*] in here~~\n");

                
                psList[k] = ExAllocatePoolWithTag(NonPagedPool, ALLOC_MAX, 'emaN'); //noteapd.exe\r <- 만큼 사이즈할당
                RtlZeroMemory(psList[k], ALLOC_MAX);
                RtlCopyMemory(psList[k], arr, i);
                psList[k][i] = '\0';
                
                DbgPrintEx(DPFLTR_IHVDRIVER_ID, 0, "[*] Data was copied! : %s\n", psList[k]);
                i+=2; // i가 다음 문자열 을 가리킨다. 
                arr += i; // change addres
                break;
            }
        }
    }
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, 0, "[*] Success StringParse!!!\n");


}

INT findIdx(ULONG psSize) {
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, 0, "\n[*] IN findIDX FUNCTION!!! %d\n",psCnt);
    int i, length=0;
    int flag = 0;
    for ( i = 0; i < psCnt; i++) {
        length = strlen(psList[i]);
        //DbgPrintEx(DPFLTR_IHVDRIVER_ID, 0, "\n[*] IN findIDX : PS name %s\n",psList[i]);
        //DbgPrintEx(DPFLTR_IHVDRIVER_ID, 0, "\n[*] IN findIDX : PS size %d\n",length );
        if (length < 5) {
            return i;
        }
    }
    psList[psCnt] = ExAllocatePoolWithTag(NonPagedPool, ALLOC_MAX, 'emaN');
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, 0, "\n[*] IN findIDX COMPELETE~~~!!!\n");
    return psCnt;
}

VOID writeAfterAdd() {
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, 0, "[**]    writeAfterAdd !  \n");
    NTSTATUS status;
    LARGE_INTEGER      byteOffset = { 0, }; // 오류 났다.,

    CHAR WRITE_BUFF[512] = { 0, };
    ZwClose(hFile);

    RtlInitUnicodeString(&uFilename, L"\\??\\C:\\file.txt");
    InitializeObjectAttributes(&oa, &uFilename, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);

    //FILE_ALL_ACCESS , FILE_SHARE_READ | FILE_SHARE_WRITE
    status = ZwOpenFile(&hFile,FILE_ALL_ACCESS, &oa, &iostatus,
        FILE_SHARE_READ, FILE_NON_DIRECTORY_FILE
    );

    for (int i = 0; i < psCnt; i++) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, 0, "[ps**]   psslite error!  : %s\n", psList[i]);
        strcat(WRITE_BUFF, psList[i]);
        strcat(WRITE_BUFF, "\r");
        strcat(WRITE_BUFF, "\n");
    }

    status = ZwWriteFile(hFile, NULL, NULL, NULL,
        &iostatus, WRITE_BUFF, strlen(WRITE_BUFF), &byteOffset, NULL);

    if (!NT_SUCCESS(status))
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, 0, "[22]    ZwWrite error!  : %x\n", status);

}

VOID deleteProcess(PCHAR userName, ULONG userLength) {
    NTSTATUS status;
    
    LARGE_INTEGER      byteOffset = { 0, }; // 오류 났다.,

    CHAR WRITE_BUFF[512] = { 0, };
    for (int i = 0; i < psCnt; i++) {
        
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, 0, "[22]    START DELETE : %s\n",psList[i]);
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, 0, "[22]    START DELETE size : %d\n", userLength);
        int flag = 1;
        for (int k = 0; k < userLength; k++) {
            if (psList[i][k] != userName[k]) {
                flag = 0; // 프로세스 명이 다를때 종료한다.
                break;
            }
        }

        if (flag) { // 모든 문자열이 같다는거
//          
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, 0, "[**]    IT IS TTTTTUREEE?? : %s\n", psList[i]);
            RtlZeroMemory(psList[i], ALLOC_MAX);
            psCnt--;
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, 0, "----------   -------------------- \n");
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, 0, "[*] Total process Count is %d.\n",psCnt);
            
            RtlMoveMemory(psList[i], psList[psCnt], ALLOC_MAX);
            ExFreePool(psList[psCnt]);

            for(int x = 0; x <psCnt; x++)
                DbgPrintEx(DPFLTR_IHVDRIVER_ID, 0, "[%d] Process Name : %s.\n", x, psList[x]);

            break;
        }
    }

    //file WRITE CODE
    ZwClose(hFile);

    RtlInitUnicodeString(&uFilename, L"\\??\\C:\\file.txt");
    
    InitializeObjectAttributes(&oa, &uFilename, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
    status = ZwDeleteFile(&oa);
    if(NT_SUCCESS(status))
        


    /// <summary>
    /// //////////////
    /// </summary>
    /// 
     RtlInitUnicodeString(&uFilename, L"\\??\\Global\\C:\\file.txt");
    InitializeObjectAttributes(&oa,&uFilename, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);

    status = ZwCreateFile(
        &hFile,
        SYNCHRONIZE | GENERIC_WRITE | GENERIC_READ,
        &oa,
        &iostatus,
        NULL,
        FILE_ATTRIBUTE_NORMAL,
        FILE_SHARE_READ,
        FILE_OPEN_IF,
        FILE_SYNCHRONOUS_IO_NONALERT | FILE_NON_DIRECTORY_FILE,
        NULL,// eabuffer
        0// ealength
    );

    if(!NT_SUCCESS(status))
       DbgPrintEx(DPFLTR_IHVDRIVER_ID, 0, "[ps**]  SSSSSSSSSSHIT~~~ %x : \n",status);


    for (int i = 0; i < psCnt; i++) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, 0, "[ps**]   psslite error!  : %s\n", psList[i]);
        strcat(WRITE_BUFF, psList[i]);
        strcat(WRITE_BUFF, "\r");
        strcat(WRITE_BUFF, "\n");
    }
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, 0, "[ps**]   Written String is  : %s\n", WRITE_BUFF);
    status = ZwWriteFile(hFile, NULL, NULL, NULL,
        &iostatus, WRITE_BUFF, strlen(WRITE_BUFF),
        &byteOffset, NULL);
    if (!NT_SUCCESS(status))
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, 0, "[22]    ZwWrite error!  : %x\n", status);

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, 0, "[22]    ZSUCCESSSSSSSSSSS !  : %x\n", status);


}


void FileRead()
{
    NTSTATUS status = STATUS_SUCCESS;

    LARGE_INTEGER      byteOffset = { 0, }; // 오류 났다.,
    CHAR contents[MAX] = { 0, };

    RtlInitUnicodeString(&uFilename, L"\\??\\C:\\file.txt");
    InitializeObjectAttributes(
        &oa,
        &uFilename,
        OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
        NULL,
        NULL);

    //FILE_ALL_ACCESS
    status = ZwOpenFile(&hFile, FILE_ALL_ACCESS, &oa, &iostatus,
        FILE_SHARE_READ, FILE_NON_DIRECTORY_FILE
    );
    if (!NT_SUCCESS(status))
    {
        
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, 0, "ZwOpenFile error!\n");
        
        //goto EXIT;
    }

    ULONG length;
   
    status = ZwReadFile(hFile, NULL, NULL, NULL, &iostatus, contents, MAX, &byteOffset, NULL);
    contents[MAX-1] = '\0';
    if (!NT_SUCCESS(status))
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, 0, "ZwReadFile error!  : %x\n", status);

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, 0, "[*]Read Contents : %s!\n", contents);

    
    status = RtlStringCbLengthA(contents, MAX, &length); // txt length 구하기
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, 0, "[*] size : %d!\n", length);
    if(!NT_SUCCESS(status))
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, 0, "RtlStringCbLengthA error!\n");


        
    

    /*----------- 추가 -----------*/
    psCnt = processCount(contents, length);
    
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, 0, "[*]efjeofj -- %d error!\n",psCnt);
    StringParse(contents, length);
}


void NotifyRoutine(PEPROCESS Process, HANDLE ProcessId, PPS_CREATE_NOTIFY_INFO   CreateInfo)
{
    wchar_t cpy_String[512] = { 0, };

    

    Process = Process; ProcessId = ProcessId;  // 컴파일경고를 없애는 방법
    if (CreateInfo == NULL) // 프로세스가 종료되는 시기에는 별 작업을 하지 않습니다
        goto exit;
    memset(g_TempString, 0, 512 * sizeof(WCHAR)); // 전역변수를 0 으로 채웁니다
    memcpy(g_TempString, CreateInfo->ImageFileName->Buffer, CreateInfo->ImageFileName->Length);
    
    
    //_wcsupr(g_TempString); // 문자열을 대문자로 
    
    LONGLONG cpy_length;
    LONGLONG tmp_length;
    UNICODE_STRING Dst;
    CHAR buff[MAX];
    //DbgPrintEx(DPFLTR_IHVDRIVER_ID, 0, "!!! Casdlfjalsdfjaljdsfl 1 : %ws \n", g_TempString);
    for (int i = 0; i < psCnt; i++) {
        ANSI_STRING ansi_tmp;
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, 0, "!!! Compare Process 1 : %ws \n", g_TempString);
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, 0, "!!! Compare Process 2  : %s\n", psList[i]);


        
        RtlStringCbLengthA(psList[i], 100, &cpy_length);
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, 0, "!!! Compare cpy_length   : %lld\n", cpy_length);

    
        //RtlZeroMemory(cpy_String, cpy_length);
        //RtlCopyMemory(cpy_String, psList[i], cpy_length);



        RtlInitAnsiString(&ansi_tmp, psList[i]);
        Dst.Buffer = &buff[0];
        Dst.Length = 0;
        Dst.MaximumLength = sizeof(buff);
        RtlAnsiStringToUnicodeString(&Dst, &ansi_tmp, TRUE);

        memset(a_tmpString, 0, 512 * sizeof(WCHAR)); // 전역변수를 0 으로 채웁니다
        //memcpy(a_tmpString, Dst, ansi_tmp.Length);

        //DbgPrintEx(DPFLTR_IHVDRIVER_ID, 0, "!!! COMPARE~~~~ 11 : %ws \n", Dst.Buffer);
        //DbgPrintEx(DPFLTR_IHVDRIVER_ID, 0, "!!! COMPARE~~~~ 22 : %ws \n", g_TempString);
        
        _wcsupr(g_TempString); _wcsupr(Dst.Buffer); // 대문자로 변경
        if(wcswcs(g_TempString, Dst.Buffer) && Dst.MaximumLength>3)
        {
            
            CreateInfo->CreationStatus = STATUS_UNSUCCESSFUL;
        }
        RtlFreeUnicodeString(&Dst);
    }   
exit:
    return;
}

void SampleDriverUnload(PDRIVER_OBJECT pDrvObj)
{
    pDrvObj = pDrvObj;
    IoDeleteDevice(MyDevice);
    IoDeleteSymbolicLink(&DeviceLink);
    for (int i = 0; i < psCnt; i++)
        ExFreePool(psList[i]);
    
    PsSetCreateProcessNotifyRoutineEx(NotifyRoutine, TRUE); // 제거를 해야 합니다
    ZwClose(hFile);
}


NTSTATUS MyIOControl(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    UNREFERENCED_PARAMETER(DeviceObject);
    PIO_STACK_LOCATION pStack;
    NTSTATUS returnStatus = STATUS_SUCCESS;
    ULONG ControlCode;
    ULONG TOTAL_LENGTH;
    PCHAR outBuf;
    PCHAR tmpBuf= NULL;
    CHAR combine[512] = { 0, };
    pStack = IoGetCurrentIrpStackLocation(Irp);
    ControlCode = pStack->Parameters.DeviceIoControl.IoControlCode;

    switch (ControlCode)
    {
    case IOCTL_ADD:
        DbgPrintEx(DPFLTR_ACPI_ID, 0, "\n IOCTL_ADD Call~~ \n");
        TOTAL_LENGTH = pStack->Parameters.DeviceIoControl.InputBufferLength;
        /*-------------------- 추가 -------------------------*/
        tmpBuf = ExAllocatePoolWithTag(NonPagedPool, ALLOC_MAX , 'emaN'); // 즉 개행 전까지 A.EXE면 총 5 + 1= 6
        if (tmpBuf)
        {
            //copy buffer
            RtlZeroMemory(tmpBuf, ALLOC_MAX);
            RtlCopyMemory(tmpBuf, Irp->AssociatedIrp.SystemBuffer, 
                pStack->Parameters.DeviceIoControl.InputBufferLength);
            tmpBuf[TOTAL_LENGTH] = '\0';
            
            int idx = findIdx(TOTAL_LENGTH);
            RtlZeroMemory(psList[idx], ALLOC_MAX);
            RtlCopyMemory(psList[idx], tmpBuf, pStack->Parameters.DeviceIoControl.InputBufferLength);
            psList[idx][TOTAL_LENGTH] = '\0';
            psCnt++;
            writeAfterAdd();
        }
        Irp->IoStatus.Information = 19;
        ExFreePool(tmpBuf);
        break;
    case IOCTL_DEL:
        TOTAL_LENGTH = pStack->Parameters.DeviceIoControl.InputBufferLength;
        tmpBuf = ExAllocatePoolWithTag(NonPagedPool, ALLOC_MAX, 'emaN');
        if (tmpBuf)
        {
            RtlZeroMemory(tmpBuf, ALLOC_MAX);
            RtlCopyMemory(tmpBuf, Irp->AssociatedIrp.SystemBuffer, TOTAL_LENGTH);
            tmpBuf[TOTAL_LENGTH] = '\0';
            deleteProcess(tmpBuf , TOTAL_LENGTH);
        }
        ExFreePool(tmpBuf);
        break;
    case IOCTL_INIT:
        DbgPrintEx(DPFLTR_ACPI_ID, 0, "\n IOCTL_INIT Call~~ \n");
        for (int i = 0; i < psCnt; i++) {
            strcat(combine, psList[i]);
            if(i != psCnt-1) // 마지막에만 |  뺀다.
                strcat(combine, "|");
        }
        RtlCopyMemory(Irp->AssociatedIrp.SystemBuffer, &combine, sizeof(combine));
        Irp->IoStatus.Information = sizeof(combine);
        
    //김병장님ㅎㄴ테 보내는 코드 추가하기 

    }   

    Irp->IoStatus.Status = STATUS_SUCCESS;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return returnStatus;
}


VOID test_add_function(CHAR* arr) {
    ULONG length = strlen(arr);
    PCHAR tmpBuf = NULL;
    tmpBuf = ExAllocatePoolWithTag(NonPagedPool, ALLOC_MAX, 'emaN');
    if (tmpBuf)
    {

        RtlZeroMemory(tmpBuf, ALLOC_MAX);
        // OOOOOO -> a.exe
        RtlCopyMemory(tmpBuf, arr,length);
        tmpBuf[length] = '\0';

        int idx = findIdx(length);
        RtlZeroMemory(psList[idx], ALLOC_MAX);
        RtlCopyMemory(psList[idx], tmpBuf, length);
        psCnt++;
        writeAfterAdd();
    }
}


void test_del_function(char *ta) {
   
    int talen = strlen(ta);
    PCHAR tmpBuf = NULL;
    
    tmpBuf = ExAllocatePoolWithTag(NonPagedPool, ALLOC_MAX, 'emaN');
    if (tmpBuf)
    {
        RtlZeroMemory(tmpBuf, ALLOC_MAX);
        RtlCopyMemory(tmpBuf, ta, talen);
        tmpBuf[talen] = '\0';
        
        deleteProcess(tmpBuf, talen);
    }

}
NTSTATUS Create_Handler(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp)
{
    Irp->IoStatus.Status = STATUS_SUCCESS;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return STATUS_SUCCESS;
}
NTSTATUS DriverEntry(PDRIVER_OBJECT pDrvObj, PUNICODE_STRING pRegPath)
{
    NTSTATUS status;
    //UNREFERENCED_PARAMETER(pRegPath);
    
    RtlInitUnicodeString(&DeviceLink, LINK_NAME);
    RtlInitUnicodeString(&DeviceName, DEVICE_NAME);


    status = IoCreateDevice( pDrvObj, 0, &DeviceName,
        FILE_DEVICE_UNKNOWN,
        FILE_DEVICE_SECURE_OPEN,
        FALSE,
        &MyDevice
    );
    //MyDevice->Flags &= ~DO_DEVICE_INITIALIZING;
    //MyDevice->Flags |= DO_BUFFERED_IO;
    if (!NT_SUCCESS(status))
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, 0, "!!! IoCreateDevice Fail! \n");

    status = IoCreateSymbolicLink(&DeviceLink, &DeviceName);


    if (!NT_SUCCESS(status))
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, 0, "!!! IoCreateSymbolicLink Fail! \n");

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, 0, "!!! Success IoCreateSymbolicLink \n");
    FileRead();
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, 0, "!!! Success FILeRead \n");
    pDrvObj->DriverUnload = SampleDriverUnload;
    pDrvObj->MajorFunction[IRP_MJ_DEVICE_CONTROL] = MyIOControl;
    pDrvObj->MajorFunction[IRP_MJ_CREATE] = Create_Handler;

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, 0, "!!!-------BEFORE ---------- \n");

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, 0, "!!!-------AFTER ---------- \n");
    


    //a.exe , b.exe 추가한다 ->a.exe 삭제 -> c.exe 추가-> b.exe 삭제

    // b + c + noteapd + c.exe
    /*
    test_add_function("a.exe");
    test_add_function("b.exe");
    test_del_function("a.exe");
    test_add_function("c.exe");
    test_del_function("calc.exe");
   */
    // Result :  c.exe. notepad.exe + b.exe 
    

    PsSetCreateProcessNotifyRoutineEx(NotifyRoutine, FALSE); // 설치를 합니다

    return STATUS_SUCCESS;
}