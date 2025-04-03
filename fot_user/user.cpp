#include <windows.h>
#include <fltUser.h>
#include <iostream>

#define COMMUNICATION_PORT_NAME L"\\FileTrackerPort"

int main()
{

    std::cout << "HELLO !!" << std::endl;
    HANDLE hPort = INVALID_HANDLE_VALUE;
    HRESULT hResult = FilterConnectCommunicationPort(COMMUNICATION_PORT_NAME, 0, NULL, 0, NULL, &hPort);

    if (FAILED(hResult)) {
        printf("Could not connect to filter: 0x%08x\n", hResult);
        return -1;
    }

    CloseHandle(hPort);

}
