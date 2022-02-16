// SPDX-License-Identifier: Apache-2.0

#include <stdio.h>
#include "minidump.h"

using namespace System;
using namespace System::Runtime::InteropServices;

int main(array<System::String ^> ^args)
{
	if (args->Length == 2) {

		int i = Int32::Parse(args[0]);
		
		MiniDump::MiniDump ^m = gcnew MiniDump::MiniDump();
		m->DumpPid(i, args[1]);

	} else {
		Console::WriteLine("Syntax: {0} <pid> <outfile>", System::AppDomain::CurrentDomain->FriendlyName);
	}

    return 0;
}
