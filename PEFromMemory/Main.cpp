#include <iostream>
#include <string>
#include <fstream>
#include <windows.h>
#include <TlHelp32.h>
#include <filesystem>

LPVOID MapFileToMemory(LPCSTR path)
{
    if (!std::filesystem::exists(path))
        return 0;
    std::streampos size;
    std::ifstream file(path, std::ios::in | std::ios::binary | std::ios::ate);
    if (file.is_open())
    {
        size = file.tellg();

        char* mem = new char[size]();

        file.seekg(0, std::ios::beg);
        file.read(mem, size);
        file.close();

        return mem;
    }
    return 0;
}

int RunPE(LPPROCESS_INFORMATION processinfo,LPSTARTUPINFO startinfo,LPVOID image,LPWSTR args)
{
    WCHAR filepath[MAX_PATH];
    if (!GetModuleFileName(NULL,filepath,sizeof(filepath)))
        return -1;
    WCHAR buffer[MAX_PATH + 2048];
    ZeroMemory(buffer, sizeof buffer);
    SIZE_T length = wcslen(filepath);
    memcpy(buffer,filepath,length * sizeof(WCHAR));
    buffer[length] = ' ';
    memcpy(buffer + length + 1,args, sizeof(args));

    PIMAGE_DOS_HEADER dosheader = reinterpret_cast<PIMAGE_DOS_HEADER>(image);
    PIMAGE_NT_HEADERS ntheader = reinterpret_cast<PIMAGE_NT_HEADERS>(reinterpret_cast<DWORD64>(image) + dosheader->e_lfanew);
    if (ntheader->Signature != IMAGE_NT_SIGNATURE)
        return -1;

    if (!CreateProcess(NULL,buffer,NULL,NULL,TRUE,CREATE_SUSPENDED,NULL,NULL,startinfo,processinfo))
        return -1;

    CONTEXT ctx;
    ZeroMemory(&ctx, sizeof ctx);
    ctx.ContextFlags = CONTEXT_FULL;
    if (!GetThreadContext(processinfo->hThread, &ctx))
    {
        TerminateProcess(processinfo->hProcess,-4);
        return -1;
    }

    LPVOID imagebase = VirtualAllocEx(processinfo->hProcess,reinterpret_cast<LPVOID>(ntheader->OptionalHeader.ImageBase),ntheader->OptionalHeader.SizeOfImage,MEM_COMMIT | MEM_RESERVE,PAGE_EXECUTE_READWRITE);
    if (imagebase == NULL)
    {
        TerminateProcess(processinfo->hProcess,-5);
        return -1;
    }

    if (!WriteProcessMemory(processinfo->hProcess,imagebase,image,ntheader->OptionalHeader.SizeOfHeaders,NULL))
    {
        TerminateProcess(processinfo->hProcess,-6);
        return -1;
    }

    for (SIZE_T i = 0;i < ntheader->FileHeader.NumberOfSections; i++)
    {
        PIMAGE_SECTION_HEADER sectionheader = reinterpret_cast<PIMAGE_SECTION_HEADER>(reinterpret_cast<DWORD64>(image) +dosheader->e_lfanew +sizeof(IMAGE_NT_HEADERS64) +sizeof(IMAGE_SECTION_HEADER) * i);

        if (!WriteProcessMemory(processinfo->hProcess,reinterpret_cast<LPVOID>(reinterpret_cast<DWORD64>(imagebase) +sectionheader->VirtualAddress),
            reinterpret_cast<LPVOID>(reinterpret_cast<DWORD64>(image) +sectionheader->PointerToRawData),sectionheader->SizeOfRawData,NULL))
        {
            TerminateProcess(processinfo->hProcess,-7);
            return -1;
        }
    }

    if (!WriteProcessMemory(processinfo->hProcess,reinterpret_cast<LPVOID>(ctx.Rdx + sizeof(LPVOID) * 2),&imagebase,sizeof(LPVOID),NULL))
    {
        TerminateProcess(processinfo->hProcess,-8);
        return -1;
    }

    ctx.Rcx = reinterpret_cast<DWORD64>(imagebase) + ntheader->OptionalHeader.AddressOfEntryPoint;
    if (!SetThreadContext(processinfo->hThread,&ctx))
    {
        TerminateProcess(processinfo->hProcess,-9);
        return -1;
    }

    if (!ResumeThread(processinfo->hThread))
    {
        TerminateProcess(processinfo->hProcess,-10);
        return -1;
    }

    return 0;
}

void main()
{
    PROCESS_INFORMATION shellcodeinfo;
    ZeroMemory(&shellcodeinfo, sizeof shellcodeinfo);
    STARTUPINFO startupinfo;
    ZeroMemory(&startupinfo, sizeof startupinfo);
    WCHAR args[] = L"";
    LPVOID shellcode = MapFileToMemory("C:\\Users\\dev\\Desktop\\PEFromMemory\\Build\\Debug\\PEFromMemory\\TestApp.exe");
    if (shellcode == 0)
    {
        std::cout << "Failed To Map File To Memory" << std::endl;
		return;
    }
    std::thread thread([&]
        {
            if (!RunPE(&shellcodeinfo, &startupinfo, reinterpret_cast<LPVOID>(shellcode), args))
            {
                WaitForSingleObject(shellcodeinfo.hProcess, INFINITE);
                DWORD returnvalue = 0;
                GetExitCodeProcess(shellcodeinfo.hProcess, &returnvalue);
                std::cout << "Exit Code: " << returnvalue << std::endl;
                CloseHandle(shellcodeinfo.hThread);
                CloseHandle(shellcodeinfo.hProcess);
            }
        });
    thread.join();
 
}