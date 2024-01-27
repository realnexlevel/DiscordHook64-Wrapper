namespace Discord
{
	uintptr_t MHCreateHookAddress = 0, MHInitializeAddress = 0, MHQueueEnableHookAddress = 0, MHApplyQueuedAddress = 0;

	// MinHook Error Codes.
	typedef enum MH_STATUS
	{
		// Unknown error. Should not be returned.
		MH_UNKNOWN = -1,

		// Successful.
		MH_OK = 0,

		// MinHook is already initialized.
		MH_ERROR_ALREADY_INITIALIZED,

		// MinHook is not initialized yet, or already uninitialized.
		MH_ERROR_NOT_INITIALIZED,

		// The hook for the specified target function is already created.
		MH_ERROR_ALREADY_CREATED,

		// The hook for the specified target function is not created yet.
		MH_ERROR_NOT_CREATED,

		// The hook for the specified target function is already enabled.
		MH_ERROR_ENABLED,

		// The hook for the specified target function is not enabled yet, or already
		// disabled.
		MH_ERROR_DISABLED,

		// The specified pointer is invalid. It points the address of non-allocated
		// and/or non-executable region.
		MH_ERROR_NOT_EXECUTABLE,

		// The specified target function cannot be hooked.
		MH_ERROR_UNSUPPORTED_FUNCTION,

		// Failed to allocate memory.
		MH_ERROR_MEMORY_ALLOC,

		// Failed to change the memory protection.
		MH_ERROR_MEMORY_PROTECT,

		// The specified module is not loaded.
		MH_ERROR_MODULE_NOT_FOUND,

		// The specified function is not found.
		MH_ERROR_FUNCTION_NOT_FOUND
	}
	MH_STATUS;

	static auto GetBase() -> uintptr_t
	{
		return
			reinterpret_cast<uintptr_t>(LI_FN(GetModuleHandleA)(Xor("DiscordHook64.dll")));
	}

	static auto SwapPresentScenePointer(PVOID NewHook) -> PVOID
	{
		auto DiscordModule = Discord::GetBase();
		if (DiscordModule == NULL)
		{
			LI_FN(MessageBoxA)((HWND)nullptr, Xor("Discord module is not loaded."), Xor("Failure"), MB_ICONERROR);
			return nullptr;
		}

		auto SizeOfImage = reinterpret_cast<PIMAGE_NT_HEADERS>(reinterpret_cast<std::uint8_t*>(DiscordModule) +
			reinterpret_cast<PIMAGE_DOS_HEADER>(DiscordModule)->e_lfanew)->OptionalHeader.SizeOfImage;

		// 48 8B 05 B1 D7 0C ?
		auto addr = Util::PatternScan(
			DiscordModule,
			SizeOfImage,
			L"\x48\x8B\x05\xB1\xD7\x0C\x00",
			L"xxxxxx?"
		);

		if (addr == NULL)
		{
			LI_FN(MessageBoxA)((HWND)nullptr, Xor("Failed to get reference to the present original function pointer."), Xor("Failure"), MB_ICONERROR);
			return nullptr;
		}

		addr = RVA(addr, 7);

		return _InterlockedExchangePointer(reinterpret_cast<volatile PVOID*>(addr), NewHook);
	}

	static auto MH_Initialize(VOID) -> MH_STATUS
	{
		if (Discord::MHInitializeAddress == NULL)
		{
			auto DiscordModule = Discord::GetBase();
			if (DiscordModule == NULL)
			{
				LI_FN(MessageBoxA)((HWND)nullptr, Xor("Discord module is not loaded."), Xor("Failure"), MB_ICONERROR);
				return MH_STATUS::MH_UNKNOWN;
			}

			auto SizeOfImage = reinterpret_cast<PIMAGE_NT_HEADERS>(reinterpret_cast<std::uint8_t*>(DiscordModule) +
				reinterpret_cast<PIMAGE_DOS_HEADER>(DiscordModule)->e_lfanew)->OptionalHeader.SizeOfImage;

			// [actual address in first opcode] E8 ? ? ? ? 85 C0 74 4F
			Discord::MHInitializeAddress = Util::PatternScan(
				DiscordModule,
				SizeOfImage,
				L"\xE8\x00\x00\x00\x00\x85\xC0\x74\x4F",
				L"x????xxxx"
			);

			if (Discord::MHInitializeAddress == NULL)
			{
				LI_FN(MessageBoxA)((HWND)nullptr, Xor("Failed to resolve MH_Initialize function."), Xor("Failure"), MB_ICONERROR);
				return MH_STATUS::MH_UNKNOWN;
			}

			Discord::MHInitializeAddress = RVA(Discord::MHInitializeAddress, 5);
		}

		return reinterpret_cast<MH_STATUS(__fastcall*)(VOID)>(Discord::MHInitializeAddress)();
	}

	static auto MH_CreateHook(LPVOID pTarget, LPVOID pDetour, LPVOID* ppOriginal) -> MH_STATUS
	{
		if (Discord::MHCreateHookAddress == NULL)
		{
			auto DiscordModule = Discord::GetBase();
			if (DiscordModule == NULL)
			{
				LI_FN(MessageBoxA)((HWND)nullptr, Xor("Discord module is not loaded."), Xor("Failure"), MB_ICONERROR);
				return MH_STATUS::MH_UNKNOWN;
			}

			auto SizeOfImage = reinterpret_cast<PIMAGE_NT_HEADERS>(reinterpret_cast<std::uint8_t*>(DiscordModule) +
				reinterpret_cast<PIMAGE_DOS_HEADER>(DiscordModule)->e_lfanew)->OptionalHeader.SizeOfImage;

			// [actual address in first opcode] E8 ? ? ? ? 85 C0 74 47
			Discord::MHCreateHookAddress = Util::PatternScan(
				DiscordModule,
				SizeOfImage,
				L"\xE8\x00\x00\x00\x00\x85\xC0\x74\x47",
				L"x????xxxx"
			);

			if (Discord::MHCreateHookAddress == NULL)
			{
				LI_FN(MessageBoxA)((HWND)nullptr, Xor("Failed to resolve MH_CreateHook function."), Xor("Failure"), MB_ICONERROR);
				return MH_STATUS::MH_UNKNOWN;
			}

			Discord::MHCreateHookAddress = RVA(Discord::MHCreateHookAddress, 5);
		}

		return reinterpret_cast<MH_STATUS(__fastcall*)(LPVOID, LPVOID, LPVOID*)>
			(Discord::MHCreateHookAddress)(pTarget, pDetour, ppOriginal);
	}

	static auto MH_QueueEnableHook(LPVOID pTarget) -> MH_STATUS
	{
		if (Discord::MHQueueEnableHookAddress == NULL)
		{
			auto DiscordModule = Discord::GetBase();
			if (DiscordModule == NULL)
			{
				LI_FN(MessageBoxA)((HWND)nullptr, Xor("Discord module is not loaded."), Xor("Failure"), MB_ICONERROR);
				return MH_STATUS::MH_UNKNOWN;
			}

			auto SizeOfImage = reinterpret_cast<PIMAGE_NT_HEADERS>(reinterpret_cast<std::uint8_t*>(DiscordModule) +
				reinterpret_cast<PIMAGE_DOS_HEADER>(DiscordModule)->e_lfanew)->OptionalHeader.SizeOfImage;

			// [actual address in first opcode] E8 ? ? ? ? 85 C0 74 18 48 8B 15
			Discord::MHQueueEnableHookAddress = Util::PatternScan(
				DiscordModule,
				SizeOfImage,
				L"\xE8\x00\x00\x00\x00\x85\xC0\x74\x18\x48\x8B\x15",
				L"x????xxxxxxx"
			);

			if (Discord::MHQueueEnableHookAddress == NULL)
			{
				LI_FN(MessageBoxA)((HWND)nullptr, Xor("Failed to resolve MH_QueueEnableHook function."), Xor("Failure"), MB_ICONERROR);
				return MH_STATUS::MH_UNKNOWN;
			}

			Discord::MHQueueEnableHookAddress = RVA(Discord::MHQueueEnableHookAddress, 5);
		}

		return reinterpret_cast<MH_STATUS(__fastcall*)(LPVOID)>(Discord::MHQueueEnableHookAddress)(pTarget);
	}

	static auto MH_ApplyQueued(VOID) -> MH_STATUS
	{
		if (Discord::MHApplyQueuedAddress == NULL)
		{
			auto DiscordModule = Discord::GetBase();
			if (DiscordModule == NULL)
			{
				LI_FN(MessageBoxA)((HWND)nullptr, Xor("Discord module is not loaded."), Xor("Failure"), MB_ICONERROR);
				return MH_STATUS::MH_UNKNOWN;
			}

			auto SizeOfImage = reinterpret_cast<PIMAGE_NT_HEADERS>(reinterpret_cast<std::uint8_t*>(DiscordModule) +
				reinterpret_cast<PIMAGE_DOS_HEADER>(DiscordModule)->e_lfanew)->OptionalHeader.SizeOfImage;

			// [actual address in first opcode] E8 ? ? ? ? 89 C7 85 C0 0F 84
			Discord::MHApplyQueuedAddress = Util::PatternScan(
				DiscordModule,
				SizeOfImage,
				L"\xE8\x00\x00\x00\x00\x89\xC7\x85\xC0\x0F\x84",
				L"x????xxxxxx"
			);

			if (Discord::MHApplyQueuedAddress == NULL)
			{
				LI_FN(MessageBoxA)((HWND)nullptr, Xor("Failed to resolve MH_ApplyQueued function."), Xor("Failure"), MB_ICONERROR);
				return MH_STATUS::MH_UNKNOWN;
			}

			Discord::MHApplyQueuedAddress = RVA(Discord::MHApplyQueuedAddress, 5);
		}

		return reinterpret_cast<MH_STATUS(__fastcall*)(VOID)>(Discord::MHApplyQueuedAddress)();
	}

	static auto HookPresentScene(LPVOID pDetour, LPVOID* ppOriginal)
	{
		auto DiscordModule = Discord::GetBase();
		if (DiscordModule == NULL)
		{
			LI_FN(MessageBoxA)((HWND)nullptr, Xor("Discord module is not loaded."), Xor("Failure"), MB_ICONERROR);
			return;
		}

		auto SizeOfImage = reinterpret_cast<PIMAGE_NT_HEADERS>(reinterpret_cast<std::uint8_t*>(DiscordModule) +
			reinterpret_cast<PIMAGE_DOS_HEADER>(DiscordModule)->e_lfanew)->OptionalHeader.SizeOfImage;

		// 55 56 57 53 48 83 EC 38 48 8D 6C 24 ? 44 89 C6
		auto addr = Util::PatternScan(
			DiscordModule,
			SizeOfImage,
			L"\x55\x56\x57\x53\x48\x83\xEC\x38\x48\x8D\x6C\x24\x00\x44\x89\xC6",
			L"xxxxxxxxxxxx?xxx"
		);

		if (addr == NULL)
		{
			LI_FN(MessageBoxA)((HWND)nullptr, Xor("Failed to resolve PresentScene function."), Xor("Failure"), MB_ICONERROR);
			return;
		}

		if (Discord::MH_Initialize() != MH_STATUS::MH_OK)
		{
			LI_FN(MessageBoxA)((HWND)nullptr, Xor("Failed to initialize Minhook instance."), Xor("Failure"), MB_ICONERROR);
			return;
		}

		if (Discord::MH_CreateHook(reinterpret_cast<LPVOID>(addr), pDetour, ppOriginal) != MH_STATUS::MH_OK)
		{
			LI_FN(MessageBoxA)((HWND)nullptr, Xor("Failed to create hook on Discord present scene handler."), Xor("Failure"), MB_ICONERROR);
			return;
		}

		if (Discord::MH_QueueEnableHook(reinterpret_cast<LPVOID>(addr)) != MH_STATUS::MH_OK)
		{
			LI_FN(MessageBoxA)((HWND)nullptr, Xor("Failed to create hook on Discord present scene handler."), Xor("Failure"), MB_ICONERROR);
			return;
		}

		if (Discord::MH_ApplyQueued() != MH_STATUS::MH_OK)
		{
			LI_FN(MessageBoxA)((HWND)nullptr, Xor("Failed to enable all queued hooks."), Xor("Failure"), MB_ICONERROR);
			return;
		}
	}
}
