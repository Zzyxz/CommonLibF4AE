#pragma once

#include "RE/Bethesda/TESObjectREFRs.h"

namespace RE
{
	class Actor;

	namespace CombatFormulas
	{
		[[nodiscard]] inline float GetWeaponDisplayAccuracy(const BGSObjectInstanceT<TESObjectWEAP>& a_weapon, Actor* a_actor)
		{
			using func_t = decltype(&CombatFormulas::GetWeaponDisplayAccuracy);
			REL::Relocation<func_t> func{ REL::ID(2209049) };
			return func(a_weapon, a_actor);
		}

		[[nodiscard]] inline float GetWeaponDisplayDamage(const BGSObjectInstanceT<TESObjectWEAP>& a_weapon, const TESAmmo* a_ammo, float a_condition)
		{
			using func_t = decltype(&CombatFormulas::GetWeaponDisplayDamage);
			REL::Relocation<func_t> func{ REL::ID(2209046) };
			return func(a_weapon, a_ammo, a_condition);
		}

		[[nodiscard]] inline float GetWeaponDisplayRange(const BGSObjectInstanceT<TESObjectWEAP>& a_weapon)
		{
			using func_t = decltype(&CombatFormulas::GetWeaponDisplayRange);
			REL::Relocation<func_t> func{ REL::ID(2209047) };
			return func(a_weapon);
		}

		[[nodiscard]] inline float GetWeaponDisplayRateOfFire(const TESObjectWEAP& a_weapon, const TESObjectWEAP::InstanceData* a_data)
		{
			using func_t = decltype(&CombatFormulas::GetWeaponDisplayRateOfFire);
			REL::Relocation<func_t> func{ REL::ID(2209048) };
			return func(a_weapon, a_data);
		}

		[[nodiscard]] inline float calcResistedPercentage(ActorValueInfo* av, float a2, float a3)
		{
			using func_t = decltype(&CombatFormulas::calcResistedPercentage);
			REL::Relocation<func_t> func{ REL::ID(2209007) };
			return func(av, a2, a3);
		}
	}
}
