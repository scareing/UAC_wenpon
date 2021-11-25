#pragma once

#include "stdafx.h"
#include <Shobjidl.h>
#include "windows.h"
#include "winternl.h"
#include <iostream>
#include "priv.h"
#include <comdef.h>
#include <winnt.h>

#pragma comment(lib,"Advapi32.lib")
#pragma comment(lib,"Shell32.lib")
#pragma comment(lib,"Ole32.lib")

using namespace std;


int Cmstp(char* arg, char* arg2);