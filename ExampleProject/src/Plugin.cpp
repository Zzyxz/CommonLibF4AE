#include "Plugin.h"

namespace
{
	[[nodiscard]] constexpr std::uint32_t PackVersion(
		std::uint32_t a_major,
		std::uint32_t a_minor,
		std::uint32_t a_build,
		std::uint32_t a_sub = 0) noexcept
	{
		return ((a_major & 0xFF) << 24) |
		       ((a_minor & 0xFF) << 16) |
		       ((a_build & 0xFFF) << 4) |
		       (a_sub & 0xF);
	}

	[[nodiscard]] constexpr F4SE::PluginVersionData MakePluginVersionData() noexcept
	{
		F4SE::PluginVersionData data{};
		data.pluginVersion = PackVersion(
			static_cast<std::uint32_t>(Version::MAJOR),
			static_cast<std::uint32_t>(Version::MINOR),
			static_cast<std::uint32_t>(Version::PATCH));

		for (std::size_t i = 0; i < Version::PROJECT.size() && i < std::size(data.name) - 1; ++i) {
			data.name[i] = Version::PROJECT[i];
		}

		data.compatibleVersions[0] = PackVersion(1, 11, 221);
		return data;
	}

	[[nodiscard]] bool InitializeLogger()
	{
#ifndef NDEBUG
		auto sink = std::make_shared<spdlog::sinks::msvc_sink_mt>();
#else
		auto path = logger::log_directory();
		if (!path) {
			return false;
		}

		*path /= fmt::format(FMT_STRING("{}.log"), Version::PROJECT);
		auto sink = std::make_shared<spdlog::sinks::basic_file_sink_mt>(path->string(), true);
#endif

		auto log = std::make_shared<spdlog::logger>("global log"s, std::move(sink));

#ifndef NDEBUG
		log->set_level(spdlog::level::trace);
#else
		log->set_level(spdlog::level::info);
		log->flush_on(spdlog::level::info);
#endif

		spdlog::set_default_logger(std::move(log));
		spdlog::set_pattern("[%H:%M:%S.%e] [%^%l%$] %v"s);
		return true;
	}
}

extern "C" DLLEXPORT constinit F4SE::PluginVersionData F4SEPlugin_Version = MakePluginVersionData();

bool Plugin::Initialize(const F4SE::LoadInterface* a_f4se)
{
	if (!InitializeLogger()) {
		return false;
	}

	if (a_f4se->IsEditor()) {
		logger::critical("loaded in editor");
		return false;
	}

	const auto ver = a_f4se->RuntimeVersion();
	if (ver != F4SE::RUNTIME_1_11_221) {
		logger::critical("unsupported runtime v{}", ver.string());
		return false;
	}

	F4SE::Init(a_f4se);
	logger::info("{} v{} loaded", Version::PROJECT, Version::NAME);
	return true;
}
