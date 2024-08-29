// Copyright (c) 2022 The PIVX Core developers
// Copyright (c) 2022 The Hemis Core developers

// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php.

#include "interfaces/tiertwo.h"

#include "bls/key_io.h"
#include "evo/deterministicgms.h"
#include "optional.h"
#include "netbase.h"
#include "evo/specialtx_validation.h" // For CheckService
#include "validation.h"
#include "wallet/wallet.h"

namespace interfaces {

std::unique_ptr<TierTwo> g_tiertwo;

bool TierTwo::isLegacySystemObsolete()
{
    return deterministicGMManager->LegacyGMObsolete();
}

bool TierTwo::isBlsPubKeyValid(const std::string& blsKey)
{
    auto opKey = bls::DecodePublic(Params(), blsKey);
    return opKey && opKey->IsValid();
}

OperationResult TierTwo::isServiceValid(const std::string& serviceStr)
{
    if (serviceStr.empty()) return false;
    const auto& params = Params();
    CService service;
    if (!Lookup(serviceStr, service, params.GetDefaultPort(), false)) {
        return {false, strprintf("invalid network address %s", serviceStr)};
    }

    CValidationState state;
    if (!CheckService(service, state)) {
        return {false, state.GetRejectReason()};
    }
    // All good
    return {true};
}

Optional<DGMData> TierTwo::getDGMData(const uint256& pro_tx_hash, const CBlockIndex* tip)
{
    if (!tip) return nullopt;
    const auto& params = Params();
    CDeterministicGMCPtr ptr_gm = deterministicGMManager->GetListForBlock(tip).GetGM(pro_tx_hash);
    if (!ptr_gm) return nullopt;
    DGMData data;
    data.ownerMainAddr = EncodeDestination(ptr_gm->pdgmState->keyIDOwner);
    data.ownerPayoutAddr = EncodeDestination(ptr_gm->pdgmState->scriptPayout);
    data.operatorPk = bls::EncodePublic(params, ptr_gm->pdgmState->pubKeyOperator.Get());
    data.operatorPayoutAddr = EncodeDestination(ptr_gm->pdgmState->scriptOperatorPayout);
    data.operatorPayoutPercentage = ptr_gm->nOperatorReward;
    data.votingAddr = EncodeDestination(ptr_gm->pdgmState->keyIDVoting);
    if (!vpwallets.empty()) {
        CWallet* p_wallet = vpwallets[0];
        data.operatorSk = p_wallet->GetStrFromTxExtraData(pro_tx_hash, "operatorSk");
    }
    return {data};
}

std::shared_ptr<DGMView> createDGMViewIfMine(CWallet* pwallet, const CDeterministicGMCPtr& dgm)
{
    bool hasOwnerKey;
    bool hasVotingKey;
    bool hasPayoutScript;
    Optional<std::string> opOwnerLabel{nullopt};
    Optional<std::string> opVotingLabel{nullopt};
    Optional<std::string> opPayoutLabel{nullopt};
    {
        LOCK(pwallet->cs_wallet);
        hasOwnerKey = pwallet->HaveKey(dgm->pdgmState->keyIDOwner);
        hasVotingKey = pwallet->HaveKey(dgm->pdgmState->keyIDVoting);

        CTxDestination dest;
        if (ExtractDestination(dgm->pdgmState->scriptPayout, dest)) {
            if (auto payoutId = boost::get<CKeyID>(&dest)) {
                hasPayoutScript = pwallet->HaveKey(*payoutId);
                auto payoutLabel = pwallet->GetNameForAddressBookEntry(*payoutId);
                if (!payoutLabel.empty()) opPayoutLabel = payoutLabel;
            }
        }

        auto ownerLabel = pwallet->GetNameForAddressBookEntry(dgm->pdgmState->keyIDOwner);
        if (!ownerLabel.empty()) opOwnerLabel = ownerLabel;

        auto votingLabel = pwallet->GetNameForAddressBookEntry(dgm->pdgmState->keyIDVoting);
        if (!votingLabel.empty()) opVotingLabel = votingLabel;
    }
    if (!hasOwnerKey && !hasVotingKey) return nullptr;

    DGMView dgmView;
    dgmView.id = dgm->GetInternalId();
    dgmView.proTxHash = dgm->proTxHash;
    dgmView.hasOwnerKey = hasOwnerKey;
    dgmView.hasVotingKey = hasVotingKey;
    dgmView.hasPayoutScript = hasPayoutScript;
    dgmView.ownerAddrLabel = opOwnerLabel;
    dgmView.votingAddrLabel = opVotingLabel;
    dgmView.payoutAddrLabel = opPayoutLabel;
    dgmView.isPoSeBanned = dgm->IsPoSeBanned();
    dgmView.service = dgm->pdgmState->addr.IsValid() ? dgm->pdgmState->addr.ToStringIPPort() : "";
    dgmView.collateralOut = dgm->collateralOutpoint;
    return std::make_shared<DGMView>(dgmView);
}

void TierTwo::refreshCache(const CDeterministicGMList& gmList)
{
    if (vpwallets.empty()) return;
    CWallet* pwallet = vpwallets[0];
    std::vector<std::shared_ptr<DGMView>> vec_dgms;
    gmList.ForEachGM(false, [pwallet, &vec_dgms](const CDeterministicGMCPtr& dgm) {
        auto opDGM = createDGMViewIfMine(pwallet, dgm);
        if (opDGM) vec_dgms.emplace_back(opDGM);
    });

    LOCK(cs_cache);
    m_cached_dgms = vec_dgms;
    m_last_block_cached = gmList.GetBlockHash();
}

void TierTwo::init()
{
    // Init the DGMs cache
    refreshCache(deterministicGMManager->GetListAtChainTip());
}

void TierTwo::NotifyGamemasterListChanged(bool undo, const CDeterministicGMList& oldGMList, const CDeterministicGMListDiff& diff)
{
    if (vpwallets.empty()) return;
    // Refresh cache if reorg occurred
    if (WITH_LOCK(cs_cache, return m_last_block_cached) != oldGMList.GetBlockHash()) {
        refreshCache(oldGMList);
    }

    CWallet* pwallet = vpwallets[0];
    LOCK (cs_cache);

    // Remove dgms
    for (const auto& removed : diff.removedGms) {
        auto it = m_cached_dgms.begin();
        while (it != m_cached_dgms.end()) {
            if (it->get()->id == removed) it = m_cached_dgms.erase(it);
            else it++;
        }
    }

    // Add dgms
    for (const auto& add : diff.addedGMs) {
        auto opDGM = createDGMViewIfMine(pwallet, add);
        if (opDGM) m_cached_dgms.emplace_back(opDGM);
    }

    // TODO: updated DGMs.

    // Update cached hash
    m_last_block_cached = diff.blockHash;
}

} // end namespace interfaces