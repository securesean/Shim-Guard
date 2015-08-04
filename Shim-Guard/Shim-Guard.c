/*
Shim Guard

Author:		Sean Pierce
Email:		sdb at securesean com
Date:		Aug 1st 2015

This is proof-of-concept code so for this version I'm waiting for the registry event to trigger so I can alert the user but malicious shim
might still get executed so in the next version I'll change the permissions on the registry key, but that's a little tricky.

I set the target compilation for XP x64 and x86 but I've only tested it on Win7 x64.
There are currently a few bugs which should be updated shortly.
*/

#include <windows.h>
#include <stdio.h>

int main(void) {
	HKEY first_hKey;
	HKEY second_hKey;
	HKEY handleArray[2];
	HANDLE hEvent;
	DWORD dwFilter;
	BOOL returned;
	static char firstShimEntry[] = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\AppCompatFlags\\Custom";
	static char secondShimEntry[] = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\AppCompatFlags\\InstalledSDB";



	//TODO: Get current values, display them and use them as a baseline for later




	// open the reg keys
	memset(&first_hKey, 0x00, sizeof(first_hKey));
	memset(&second_hKey, 0x00, sizeof(second_hKey));
	returned = RegOpenKeyEx(HKEY_LOCAL_MACHINE, firstShimEntry, 0, KEY_NOTIFY, &first_hKey); // for HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Custom    KEY_ALL_ACCESS for later
	if (returned != ERROR_SUCCESS){
		switch (returned){
		case ERROR_ACCESS_DENIED:
			printf("Openning REg Key Failed: Access Denied\n");
			break;
		case ERROR_INVALID_HANDLE:
			printf("Openning REg Key Failed. Error: Invalid Handle\n");
			break;
		default:
			printf("Error in Opening Key. Returned: %d. GetLastError: %x\n", returned, GetLastError());
		}
	}

	returned = RegOpenKeyEx(HKEY_LOCAL_MACHINE, secondShimEntry, 0, KEY_NOTIFY, &second_hKey); // for HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\InstalledSDB    KEY_ALL_ACCESS for later
	if (returned != ERROR_SUCCESS){
		switch (returned){
		case ERROR_ACCESS_DENIED:
			printf("Openning REg Key Failed: Access Denied\n");
			break;
		case ERROR_INVALID_HANDLE:
			printf("Openning REg Key Failed. Error: Invalid Handle\n");
			break;
		default:
			printf("Error in Opening Key. Returned: %d. GetLastError: %x\n", returned, GetLastError());
		}
	}


	// Set notify events
	hEvent = CreateEvent(NULL, FALSE, FALSE, NULL);
	dwFilter = REG_NOTIFY_CHANGE_NAME | REG_NOTIFY_CHANGE_LAST_SET;
	DWORD notifyOnFirstKey = ERROR_SUCCESS;
	notifyOnFirstKey = RegNotifyChangeKeyValue(first_hKey, TRUE, dwFilter, hEvent, TRUE);
	if (notifyOnFirstKey != ERROR_SUCCESS){
		switch (notifyOnFirstKey){
		case ERROR_ACCESS_DENIED:
			printf("Notify on Reg Key Failed: Access Denied\n");
			break;
		case ERROR_INVALID_HANDLE:
			printf("Notify on Reg Key Failed. Error: Invalid Handle\n");
			break;
		default:
			printf("Error in Watching Key: %s. Returned: %d. GetLastError: %x\n", secondShimEntry, notifyOnFirstKey, GetLastError());
		}
	}

	DWORD notifyOnSecondKey = RegNotifyChangeKeyValue(second_hKey, TRUE, dwFilter, hEvent, TRUE);
	if (notifyOnSecondKey != ERROR_SUCCESS){
		switch (notifyOnSecondKey){
		case ERROR_ACCESS_DENIED:
			printf("Notify on Reg Key Failed: Access Denied\n");
			break;
		case ERROR_INVALID_HANDLE:
			printf("Notify on Reg Key Failed. Error: Invalid Handle\n");
			break;
		default:
			printf("Error in Watching Key: %s. Returned: %d. GetLastError: %x\n", firstShimEntry, notifyOnSecondKey, GetLastError());
		}
	}



	// start monitoring loop
	if (notifyOnFirstKey != ERROR_SUCCESS && notifyOnSecondKey != ERROR_SUCCESS){
		printf("Fatal: Cannot Monitor any keys\n");
		return 3;
	}
	else {
		printf("Now Monitoring Registry Keys\n");
	}

	handleArray[0] = first_hKey;
	handleArray[1] = second_hKey;
	int lastError = ERROR_SUCCESS;
	BOOL bWaitAll = FALSE;
	DWORD WaitForError = 0;
	while (TRUE) {
		//WaitForSingleObject(hEvent, INFINITE);
		WaitForError = WaitForMultipleObjects(2, handleArray, bWaitAll, INFINITE);
		switch (WaitForError){
		case WAIT_OBJECT_0:
			printf("Key change in %s\n", firstShimEntry);
			//TODO: Get registry values. Remove the values not found in the base line.

			printf("An Registry Key was altered in the Custom Shim folder.\n");
			RegNotifyChangeKeyValue(first_hKey, TRUE, dwFilter, hEvent, TRUE);

			break;
		case 1:
			printf("Key change in %s\n", secondShimEntry);
			//TODO: Get registry values. Remove the values not found in the base line.

			printf("An Registry Key was altered in the Install Shim Location folder.\n");
			RegNotifyChangeKeyValue(second_hKey, TRUE, dwFilter, hEvent, TRUE);

			break;
		case WAIT_ABANDONED_0:
			printf("Wait was Abandoned. This should never happen when Infinite time was specified\n");
			break;
		case WAIT_TIMEOUT:
			printf("Wait Timed out. This should never happen when Infinite time was specified\n");
			break;
		case WAIT_FAILED:
			lastError = GetLastError();
			if (lastError == ERROR_ACCESS_DENIED){
				printf("Wait failed. Error: Access Denied\n");
			}
			else{
				printf("Wait failed. Error: %#x\n", lastError);
			}
			break;
		default:
			printf("Unknown Error in WaitForMultipleObjects. EGet last Error: %#x\n", GetLastError());
		}
	}

	return 0;
}