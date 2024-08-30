// Copyright (c) 2019-2022 The Hemis Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "qt/Hemis/gmmodel.h"
#include "bls/key_io.h"
#include "coincontrol.h"
#include "evo/deterministicgms.h"
#include "interfaces/tiertwo.h"
#include "evo/specialtx_utils.h"

#include "coincontrol.h"
#include "gamemaster.h"
#include "gamemasterman.h"
#include "net.h" // for validateGamemasterIP
#include "netbase.h"
#include "operationresult.h"
#include "primitives/transaction.h"
#include "qt/bitcoinunits.h"
#include "qt/optionsmodel.h"
#include "qt/Hemis/guitransactionsutils.h"
#include "wallet/wallet.h" // TODO: Move to walletModel
#include "qt/walletmodel.h"
#include "qt/walletmodeltransaction.h"
#include "tiertwo/tiertwo_sync_state.h"
#include "uint256.h"

#include <QFile>
#include <QHostAddress>
#include <cstddef>

uint16_t GamemasterWrapper::getType() const
{
    if (!dgmView) {
        return LEGACY;
    }

    uint16_t type = 0;
    if (dgmView->hasOwnerKey) {
        type |= DGM_OWNER;
    }

    if (dgmView->hasVotingKey) {
        type |= DGM_VOTER;
    }

    // todo: add operator
    return type;
}

GMModel::GMModel(QObject *parent) : QAbstractTableModel(parent) {}

void GMModel::init()
{
    updateGMList();
}

void GMModel::updateGMList()
{
    int gmMinConf = getGamemasterCollateralMinConf();
    nodes.clear();
    collateralTxAccepted.clear();
    for (const CGamemasterConfig::CGamemasterEntry& gme : gamemasterConfig.getEntries()) {
        int nIndex;
        if (!gme.castOutputIndex(nIndex)) continue;

        const uint256& txHash = uint256S(gme.getTxHash());
        CTxIn txIn(txHash, uint32_t(nIndex));
        CGamemaster* pgm = gamemasterman.Find(txIn.prevout);
        nodes.append(GamemasterWrapper(
                QString::fromStdString(gme.getAlias()),
                QString::fromStdString(gme.getIp()),
                pgm,
                pgm ? pgm->vin.prevout : txIn.prevout,
                Optional<QString>(QString::fromStdString(gme.getPubKeyStr())),
                nullptr) // dgm view
        );

        if (walletModel) {
            collateralTxAccepted.insert(gme.getTxHash(), walletModel->getWalletTxDepth(txHash) >= gmMinConf);
        }
    }

    // Now add DGMs
    for (const auto& dgm : interfaces::g_tiertwo->getKnownDGMs()) {
        // Try the owner address as "alias", if not found use the payout script, if not, use the voting address, if not use the service.
        std::string alias;
        if (dgm->hasOwnerKey && dgm->ownerAddrLabel) {
            alias = *dgm->ownerAddrLabel;
        } else if (dgm->hasPayoutScript && dgm->payoutAddrLabel) {
            alias = *dgm->payoutAddrLabel;
        } else if (dgm->hasVotingKey && dgm->votingAddrLabel) {
            alias = *dgm->votingAddrLabel;
        } else if (!dgm->service.empty()) {
            alias = dgm->service;
        } else {
            // future think: could use the proTxHash if no label is found.
            alias = "no alias available";
        }

        nodes.append(GamemasterWrapper(
                QString::fromStdString(alias),
                QString::fromStdString(dgm->service),
                nullptr,
                dgm->collateralOut,
                nullopt,
                dgm));

        if (walletModel) {
            const auto& txHash = dgm->collateralOut.hash;
            collateralTxAccepted.insert(txHash.GetHex(), walletModel->getWalletTxDepth(txHash) >= gmMinConf);
        }
    }

    Q_EMIT dataChanged(index(0, 0, QModelIndex()),
                       index(nodes.size(), ColumnIndex::COLUMN_COUNT, QModelIndex()));
}

int GMModel::rowCount(const QModelIndex &parent) const
{
    if (parent.isValid())
        return 0;
    return nodes.size();
}

int GMModel::columnCount(const QModelIndex &parent) const
{
    if (parent.isValid())
        return 0;
    return ColumnIndex::COLUMN_COUNT;
}
static QString formatTooltip(const GamemasterWrapper& wrapper)
{
    return QObject::tr((wrapper.getType() == GMViewType::LEGACY) ?
            "Legacy Gamemaster\nIt will be disabled after v6.0 enforcement" :
            "Deterministic Gamemaster");
}

QVariant GMModel::data(const QModelIndex &index, int role) const
{
    if (!index.isValid())
        return QVariant();

    // rec could be null, always verify it.
    int row = index.row();
    const GamemasterWrapper& gmWrapper = nodes.at(row);
    switch (role) {
    case Qt::DisplayRole:
    case Qt::EditRole: {
        switch (index.column()) {
            case ALIAS:
                return gmWrapper.label;
            case ADDRESS:
                return gmWrapper.ipPort;
            case PUB_KEY:
                return gmWrapper.gmPubKey ? *gmWrapper.gmPubKey : "Not available";
            case COLLATERAL_ID:
                return gmWrapper.collateralId ? QString::fromStdString(gmWrapper.collateralId->hash.GetHex()) : "Not available";
            case COLLATERAL_OUT_INDEX:
                return gmWrapper.collateralId ? QString::number(gmWrapper.collateralId->n) : "Not available";
            case STATUS: {
                std::string status = "MISSING";
                if (gmWrapper.dgmView) {
                    // Deterministic GM
                    status = gmWrapper.dgmView->isPoSeBanned ? "PoSe BANNED" : "ENABLED";
                } else {
                    // Legacy GM
                    if (gmWrapper.gamemaster) {
                        status = gmWrapper.gamemaster->Status();
                        // Quick workaround to the current Gamemaster status types.
                        // If the status is REMOVE and there is no pubkey associated to the Gamemaster
                        // means that the GM is not in the network list and was created in
                        // updateGMList(). Which.. denotes a not started gamemaster.
                        // This will change in the future with the GamemasterWrapper introduction.
                        if (status == "REMOVE" && !gmWrapper.gamemaster->pubKeyCollateralAddress.IsValid()) {
                            return "MISSING";
                        }
                    }
                }
                return QString::fromStdString(status);
            }
            case PRIV_KEY: {
                if (gmWrapper.collateralId) {
                    for (const CGamemasterConfig::CGamemasterEntry& gme : gamemasterConfig.getEntries()) {
                        if (gme.getTxHash() == gmWrapper.collateralId->hash.GetHex()) {
                            return QString::fromStdString(gme.getPrivKey());
                        }
                    }
                }
                return "Not available";
            }
            case WAS_COLLATERAL_ACCEPTED:{
                return gmWrapper.collateralId && collateralTxAccepted.value(gmWrapper.collateralId->hash.GetHex());
            }
            case TYPE:{
                return gmWrapper.getType();
            }
            case IS_POSE_ENABLED:{
                return gmWrapper.dgmView && !gmWrapper.dgmView->isPoSeBanned;
            }
            case PRO_TX_HASH:{
                if (gmWrapper.dgmView) return QString::fromStdString(gmWrapper.dgmView->proTxHash.GetHex());
            }
        }
    }
    case Qt::ToolTipRole:
        return formatTooltip(gmWrapper);
    } // end role switch
    return QVariant();
}


bool GMModel::removeGm(const QModelIndex& modelIndex)
{
    int idx = modelIndex.row();
    beginRemoveRows(QModelIndex(), idx, idx);
    auto gmWrapper = nodes.at(idx);
    if (gmWrapper.collateralId) collateralTxAccepted.remove(gmWrapper.collateralId->hash.GetHex());
    nodes.removeAt(idx);
    endRemoveRows();
    Q_EMIT dataChanged(index(idx, 0, QModelIndex()), index(idx, 5, QModelIndex()) );
    return true;
}

bool GMModel::addGm(CGamemasterConfig::CGamemasterEntry* gme)
{
    beginInsertRows(QModelIndex(), nodes.size(), nodes.size());
    int nIndex;
    if (!gme->castOutputIndex(nIndex))
        return false;

    COutPoint collateralId = COutPoint(uint256S(gme->getTxHash()), uint32_t(nIndex));
    CGamemaster* pgm = gamemasterman.Find(collateralId);
    nodes.append(GamemasterWrapper(
                 QString::fromStdString(gme->getAlias()),
                 QString::fromStdString(gme->getIp()),
                 pgm, pgm ? pgm->vin.prevout : collateralId,
                 Optional<QString>(QString::fromStdString(gme->getPubKeyStr())),
                 nullptr));
    endInsertRows();
    return true;
}

const GamemasterWrapper* GMModel::getGMWrapper(const QString& gmAlias)
{
    for (const auto& it : nodes) {
        if (it.label == gmAlias) {
            return &it;
        }
    }
    return nullptr;
}

int GMModel::getGMState(const QString& gmAlias)
{
    const GamemasterWrapper* gm = getGMWrapper(gmAlias);
    if (!gm) {
        throw std::runtime_error(std::string("Gamemaster alias not found"));
    }
    return gm->gamemaster ? gm->gamemaster->GetActiveState() : -1;
}

bool GMModel::isGMInactive(const QString& gmAlias)
{
    int activeState = getGMState(gmAlias);
    return activeState == CGamemaster::GAMEMASTER_EXPIRED || activeState == CGamemaster::GAMEMASTER_REMOVE;
}

bool GMModel::isGMActive(const QString& gmAlias)
{
    int activeState = getGMState(gmAlias);
    return activeState == CGamemaster::GAMEMASTER_PRE_ENABLED || activeState == CGamemaster::GAMEMASTER_ENABLED;
}

bool GMModel::isGMCollateralMature(const QString& gmAlias)
{
    const GamemasterWrapper* gm = getGMWrapper(gmAlias);
    if (!gm) {
        throw std::runtime_error(std::string("Gamemaster alias not found"));
    }
    return gm->collateralId && collateralTxAccepted.value(gm->collateralId->hash.GetHex());
}

bool GMModel::isLegacySystemObsolete()
{
    return interfaces::g_tiertwo->isLegacySystemObsolete();
}

bool GMModel::isGMsNetworkSynced()
{
    return g_tiertwo_sync_state.IsSynced();
}

bool GMModel::validateGMIP(const QString& addrStr)
{
    return validateGamemasterIP(addrStr.toStdString());
}

CAmount GMModel::getGMCollateralRequiredAmount()
{
    return Params().GetConsensus().nGMCollateralAmt;
}

int GMModel::getGamemasterCollateralMinConf()
{
    return Params().GetConsensus().GamemasterCollateralMinConf();
}

// Add here only the errors that the user could face
std::string translateRejectionError(const std::string& rejection)
{
    if (rejection == "bad-protx-ipaddr-port") {
        return _("Invalid service IP address");
    } else if (rejection == "bad-protx-dup-IP-address") {
        return _("The provided service IP address is already in use by another registered Gamemaster");
    }
    return rejection;
}

CallResult<uint256> GMModel::createDGMInternal(const Optional<COutPoint>& collateral,
    const Optional<QString>& addr_label,
    const Optional<CKey>& keyCollateral,
    const CService& service,
    const CKeyID& ownerAddr,
    const CBLSPublicKey& operatorPubKey,
    const Optional<CKeyID>& votingAddr,
    const CKeyID& payoutAddr,
    const Optional<CBLSSecretKey>& operatorSk,
    const Optional<uint16_t>& operatorPercentage,
    const Optional<CKeyID>& operatorPayoutAddr)
{
    ProRegPL pl;
    pl.nVersion = ProRegPL::CURRENT_VERSION;
    pl.addr = service;
    pl.keyIDOwner = ownerAddr;
    pl.pubKeyOperator = operatorPubKey;
    pl.keyIDVoting = votingAddr ? *votingAddr : pl.keyIDOwner;
    pl.collateralOutpoint = (collateral ? *collateral : COutPoint(UINT256_ZERO, 0)); // dummy outpoint if collateral is nullopt
    pl.scriptPayout = GetScriptForDestination(payoutAddr);
    if (operatorPayoutAddr) {
        pl.nOperatorReward = *operatorPercentage;
        pl.scriptOperatorPayout = GetScriptForDestination(*operatorPayoutAddr);
    }
    // make sure fee calculation works
    pl.vchSig.resize(CPubKey::COMPACT_SIGNATURE_SIZE);

    std::map<std::string, std::string> extraValues;
    if (operatorSk) {
        // Only if the operator sk was provided
        extraValues.emplace("operatorSk", bls::EncodeSecret(Params(), *operatorSk));
    }
    auto wallet = vpwallets[0]; // TODO: Move to walletModel
    if (collateral) {
        if (!keyCollateral) {
            return CallResult<uint256>("null key collateral");
        }
        CMutableTransaction tx;
        tx.nVersion = CTransaction::TxVersion::SAPLING;
        tx.nType = CTransaction::TxType::PROREG;
        auto res = FundSpecialTx(wallet, tx, pl);
        if (!res) return {res.getError()};

        res = SignSpecialTxPayloadByString(pl, *keyCollateral);
        if (!res) return {res.getError()};
        res = SignAndSendSpecialTx(wallet, tx, pl, &extraValues);
        return res ? CallResult<uint256>(tx.GetHash()) :
                     CallResult<uint256>(translateRejectionError(res.getError()));
    } else {
        if (!addr_label) {
            return CallResult<uint256>("Null address label");
        }
        std::string alias = addr_label->toStdString();
        CTransactionRef ret_tx;
        auto r = walletModel->getNewAddress(alias);
        QString returnStr;

        // CmutTx used only to compute the size of payload
        CMutableTransaction tx_test;
        tx_test.nVersion = CTransaction::TxVersion::SAPLING;
        tx_test.nType = CTransaction::TxType::PROREG;
        SetTxPayload(tx_test, pl);
        const int nExtraSize = int(GetSerializeSize(tx_test.extraPayload) + GetSerializeSize(tx_test.sapData));

        COutPoint collateral_outpoint;
        if (!r) return CallResult<uint256>(translateRejectionError(r.getError()));
        if (!createDGMInternalCollateral(*addr_label,
                QString::fromStdString(r.getObjResult()->ToString()),
                ret_tx,
                collateral_outpoint,
                returnStr, nExtraSize)) {
            // error str set internally
            return CallResult<uint256>(returnStr.toStdString());
        }
        pl.collateralOutpoint = collateral_outpoint;
        CMutableTransaction tx = CMutableTransaction(*ret_tx);
        tx.nVersion = CTransaction::TxVersion::SAPLING;
        tx.nType = CTransaction::TxType::PROREG;
        pl.vchSig.clear();
        UpdateSpecialTxInputsHash(tx, pl);
        auto res = SignAndSendSpecialTx(wallet, tx, pl, &extraValues);
        return res ? CallResult<uint256>(tx.GetHash()) :
                     CallResult<uint256>(translateRejectionError(res.getError()));
    }
}

CallResult<uint256> GMModel::createDGM(const std::string& alias,
    const Optional<COutPoint>& collateral,
    const Optional<QString>& addr_label,
    std::string& serviceAddr,
    const std::string& servicePort,
    const CKeyID& ownerAddr,
    const Optional<std::string>& operatorPubKey,
    const Optional<CKeyID>& votingAddr,
    const CKeyID& payoutKeyId,
    std::string& strError,
    const Optional<uint16_t>& operatorPercentage,
    const Optional<CKeyID>& operatorPayoutAddr)
{
    // Different DGM creation types:
    // 1. internal.
    // 2. external.
    // 3. fund.

    auto p_wallet = vpwallets[0]; // TODO: Move to walletModel
    const auto& chainparams = Params();

    // 1) Create the simplest DGM, the collateral was generated by this wallet.
    CService service;
    if (!serviceAddr.empty()) {
        if (!Lookup(serviceAddr + ":" + servicePort, service, chainparams.GetDefaultPort(), false)) {
            strError = strprintf("invalid network address %s", serviceAddr);
            return {strError};
        }
    }

    CPubKey pubKeyCollateral;
    Optional<CKey> keyCollateral = nullopt;

    if (collateral) {
        keyCollateral = CKey();
        if (!p_wallet->GetGamemasterVinAndKeys(pubKeyCollateral, *keyCollateral, *collateral, false, strError)) {
            return {strError};
        }
    }

    // parse operator pubkey or create one
    Optional<CBLSSecretKey> operatorSk{nullopt};
    CBLSPublicKey operatorPk;
    if (operatorPubKey) {
        auto opPk = bls::DecodePublic(Params(), *operatorPubKey);
        if (!opPk || !opPk->IsValid()) {
            strError = "invalid operator pubkey";
            return {strError};
        }
        operatorPk = *opPk;
    } else {
        // Stored within the register tx
        operatorSk = CBLSSecretKey();
        operatorSk->MakeNewKey();
        operatorPk = operatorSk->GetPublicKey();
    }

    auto res = createDGMInternal(collateral,
        addr_label,
        keyCollateral,
        service,
        ownerAddr,
        operatorPk,
        votingAddr,          // voting key
        payoutKeyId,         // payout script
        operatorSk,          // only if the operator was provided (or locally created)
        operatorPercentage,  // operator percentage
        operatorPayoutAddr); // operator payout keyid
    if (!res) {
        strError = res.getError();
        return {strError};
    }

    // All good
    return res;
}
// unban a Pose-banned DGM
bool GMModel::unbanDGM(CBLSSecretKey& operatorKey, uint256 proTxHash, std::string& strError)
{
    ProUpServPL pl;
    pl.nVersion = ProUpServPL::CURRENT_VERSION;
    pl.proTxHash = proTxHash;
    auto dgm = deterministicGMManager->GetListAtChainTip().GetGM(pl.proTxHash); // make sure that the wallet is synced first?
    if (!dgm) {
        strError = "Gamemaster not found";
        return false;
    }
    if (!dgm->IsPoSeBanned()) {
        strError = "Gamermaster is not Pose-banned";
        return false;
    }
    pl.addr = dgm->pdgmState->addr;
    pl.scriptOperatorPayout = dgm->pdgmState->scriptOperatorPayout;

    CMutableTransaction tx;
    tx.nVersion = CTransaction::TxVersion::SAPLING;
    tx.nType = CTransaction::TxType::PROUPSERV;

    auto wallet = vpwallets[0]; // TODO: Move to walletModel
    auto res = FundSpecialTx(wallet, tx, pl);
    if (!res) {
        strError = res.getError();
        return false;
    }
    res = SignSpecialTxPayloadByHash(tx, pl, operatorKey);
    if (!res) {
        strError = res.getError();
        return false;
    }
    res = SignAndSendSpecialTx(wallet, tx, pl);
    if (!res) {
        strError = res.getError();
        return false;
    }
    return true;
}
OperationResult GMModel::killDGM(const uint256& collateralHash, unsigned int outIndex)
{
    auto p_wallet = vpwallets[0]; // TODO: Move to walletModel
    const auto& tx = p_wallet->GetWalletTx(collateralHash);
    if (!tx || outIndex >= tx->tx->vout.size()) return {false, "collateral not found"};
    const auto& output = tx->tx->vout[outIndex];

    COutPoint collateral_output(collateralHash, outIndex);
    CCoinControl coinControl;
    coinControl.Select(collateral_output);
    QList<SendCoinsRecipient> recipients;
    auto ownAddr = walletModel->getNewAddress("");
    if (!ownAddr) return {false, ownAddr.getError()};
    CAmount amountToSend = output.nValue - CWallet::minTxFee.GetFeePerK();
    recipients.push_back(SendCoinsRecipient{QString::fromStdString(ownAddr.getObjResult()->ToString()), "", amountToSend, ""});
    WalletModelTransaction currentTransaction(recipients);
    walletModel->unlockCoin(collateral_output);
    WalletModel::SendCoinsReturn prepareStatus = walletModel->prepareTransaction(&currentTransaction, &coinControl, false);

    CClientUIInterface::MessageBoxFlags informType;
    QString returnMsg = GuiTransactionsUtils::ProcessSendCoinsReturn(
        prepareStatus,
        walletModel,
        informType, // this flag is not needed
        BitcoinUnits::formatWithUnit(walletModel->getOptionsModel()->getDisplayUnit(),
            currentTransaction.getTransactionFee()),
        true);

    if (prepareStatus.status != WalletModel::OK) {
        walletModel->lockCoin(collateral_output);
        return {false, returnMsg.toStdString()};
    }

    WalletModel::SendCoinsReturn sendStatus = walletModel->sendCoins(currentTransaction);
    returnMsg = GuiTransactionsUtils::ProcessSendCoinsReturn(sendStatus, walletModel, informType);
    if (sendStatus.status != WalletModel::OK) {
        walletModel->lockCoin(collateral_output);
        return {false, returnMsg.toStdString()};
    }

    return {true};
}
// This functions create a collateral that will be "locked" inside the ProRegTx (so INTERNAL collateral)
bool GMModel::createDGMInternalCollateral(
    const QString& alias,
    const QString& addr,
    CTransactionRef& ret_tx,
    COutPoint& ret_outpoint,
    QString& ret_error,
    int nExtraSize)
{
    SendCoinsRecipient sendCoinsRecipient(addr, alias, getGMCollateralRequiredAmount(), "");

    // Send the 10 tx to one of your address
    QList<SendCoinsRecipient> recipients;
    recipients.append(sendCoinsRecipient);
    WalletModelTransaction currentTransaction(recipients);
    WalletModel::SendCoinsReturn prepareStatus;
    // no coincontrol, no P2CS delegations
    prepareStatus = walletModel->prepareTransaction(&currentTransaction, nullptr, false, nExtraSize);
    ret_tx = currentTransaction.getTransaction();

    QString returnMsg = tr("Unknown error");
    // process prepareStatus and on error generate message shown to user
    CClientUIInterface::MessageBoxFlags informType;
    returnMsg = GuiTransactionsUtils::ProcessSendCoinsReturn(
        prepareStatus,
        walletModel,
        informType, // this flag is not needed
        BitcoinUnits::formatWithUnit(walletModel->getOptionsModel()->getDisplayUnit(),
            currentTransaction.getTransactionFee()),
        true);

    if (prepareStatus.status != WalletModel::OK) {
        ret_error = tr("Prepare game master failed.\n\n%1\n").arg(returnMsg);
        return false;
    }

    int indexOut = -1;
    for (int i = 0; i < (int)ret_tx->vout.size(); i++) {
        const CTxOut& out = ret_tx->vout[i];
        if (out.nValue == getGMCollateralRequiredAmount()) {
            indexOut = i;
            break;
        }
    }
    if (indexOut == -1) {
        ret_error = tr("Invalid collateral output index");
        return false;
    }
    // save the collateral outpoint
    ret_outpoint = COutPoint(UINT256_ZERO, indexOut); // generalise to second case
    return true;
}

// This functions creates and send an EXTERNAL collateral the ProRegTx will just reference it
bool GMModel::createDGMExternalCollateral(
    const QString& alias,
    const QString& addr,
    COutPoint& ret_outpoint,
    QString& ret_error)
{
    SendCoinsRecipient sendCoinsRecipient(addr, alias, getGMCollateralRequiredAmount(), "");

    // Send the 10 tx to one of your address
    QList<SendCoinsRecipient> recipients;
    recipients.append(sendCoinsRecipient);
    WalletModelTransaction currentTransaction(recipients);
    WalletModel::SendCoinsReturn prepareStatus;

    // no P2CS delegations
    prepareStatus = walletModel->prepareTransaction(&currentTransaction, coinControl, false);
    QString returnMsg = tr("Unknown error");
    // process prepareStatus and on error generate message shown to user
    CClientUIInterface::MessageBoxFlags informType;
    returnMsg = GuiTransactionsUtils::ProcessSendCoinsReturn(
        prepareStatus,
        walletModel,
        informType, // this flag is not needed
        BitcoinUnits::formatWithUnit(walletModel->getOptionsModel()->getDisplayUnit(),
            currentTransaction.getTransactionFee()),
        true);

    if (prepareStatus.status != WalletModel::OK) {
        ret_error = tr("Prepare game master failed.\n\n%1\n").arg(returnMsg);
        return false;
    }

    WalletModel::SendCoinsReturn sendStatus = walletModel->sendCoins(currentTransaction);
    // process sendStatus and on error generate message shown to user
    returnMsg = GuiTransactionsUtils::ProcessSendCoinsReturn(sendStatus, walletModel, informType);

    if (sendStatus.status != WalletModel::OK) {
        ret_error = tr("Cannot send collateral transaction.\n\n%1").arg(returnMsg);
        return false;
    }

    // look for the tx index of the collateral
    CTransactionRef walletTx = currentTransaction.getTransaction();
    std::string txID = walletTx->GetHash().GetHex();
    int indexOut = -1;
    for (int i = 0; i < (int)walletTx->vout.size(); i++) {
        const CTxOut& out = walletTx->vout[i];
        if (out.nValue == getGMCollateralRequiredAmount()) {
            indexOut = i;
            break;
        }
    }
    if (indexOut == -1) {
        ret_error = tr("Invalid collateral output index");
        return false;
    }
    // save the collateral outpoint
    ret_outpoint = COutPoint(walletTx->GetHash(), indexOut);
    return true;
}

bool GMModel::startLegacyGM(const CGamemasterConfig::CGamemasterEntry& gme, int chainHeight, std::string& strError)
{
    CGamemasterBroadcast gmb;
    if (!CGamemasterBroadcast::Create(gme.getIp(), gme.getPrivKey(), gme.getTxHash(), gme.getOutputIndex(), strError, gmb, false, chainHeight))
        return false;

    gamemasterman.UpdateGamemasterList(gmb);
    if (activeGamemaster.pubKeyGamemaster == gmb.GetPubKey()) {
        activeGamemaster.EnableHotColdGameMaster(gmb.vin, gmb.addr);
    }
    gmb.Relay();
    return true;
}

void GMModel::startAllLegacyGMs(bool onlyMissing, int& amountOfGmFailed, int& amountOfGmStarted,
                                std::string* aliasFilter, std::string* error_ret)
{
    for (const auto& gme : gamemasterConfig.getEntries()) {
        if (!aliasFilter) {
            // Check for missing only
            QString gmAlias = QString::fromStdString(gme.getAlias());
            if (onlyMissing && !isGMInactive(gmAlias)) {
                if (!isGMActive(gmAlias))
                    amountOfGmFailed++;
                continue;
            }

            if (!isGMCollateralMature(gmAlias)) {
                amountOfGmFailed++;
                continue;
            }
        } else if (*aliasFilter != gme.getAlias()){
            continue;
        }

        std::string ret_str;
        if (!startLegacyGM(gme, walletModel->getLastBlockProcessedNum(), ret_str)) {
            amountOfGmFailed++;
            if (error_ret) *error_ret = ret_str;
        } else {
            amountOfGmStarted++;
        }
    }
}

// Future: remove after v6.0
CGamemasterConfig::CGamemasterEntry* GMModel::createLegacyGM(COutPoint& collateralOut,
                             const std::string& alias,
                             std::string& serviceAddr,
                             const std::string& port,
                             const std::string& gmKeyString,
                             const std::string& gmPubKeyStr,
                             QString& ret_error)
{
    // Update the conf file
    QString strConfFileQt(Hemis_GAMEMASTER_CONF_FILENAME);
    std::string strConfFile = strConfFileQt.toStdString();
    std::string strDataDir = GetDataDir().string();
    fs::path conf_file_path(strConfFile);
    if (strConfFile != conf_file_path.filename().string()) {
        throw std::runtime_error(strprintf(_("%s %s resides outside data directory %s"), strConfFile, strConfFile, strDataDir));
    }

    fs::path pathBootstrap = GetDataDir() / strConfFile;
    if (!fs::exists(pathBootstrap)) {
        ret_error = tr("%1 file doesn't exists").arg(strConfFileQt);
        return nullptr;
    }

    fs::path pathGamemasterConfigFile = GetGamemasterConfigFile();
    fsbridge::ifstream streamConfig(pathGamemasterConfigFile);

    if (!streamConfig.good()) {
        ret_error = tr("Invalid %1 file").arg(strConfFileQt);
        return nullptr;
    }

    int linenumber = 1;
    std::string lineCopy;
    for (std::string line; std::getline(streamConfig, line); linenumber++) {
        if (line.empty()) continue;

        std::istringstream iss(line);
        std::string comment, alias, ip, privKey, txHash, outputIndex;

        if (iss >> comment) {
            if (comment.at(0) == '#') continue;
            iss.str(line);
            iss.clear();
        }

        if (!(iss >> alias >> ip >> privKey >> txHash >> outputIndex)) {
            iss.str(line);
            iss.clear();
            if (!(iss >> alias >> ip >> privKey >> txHash >> outputIndex)) {
                streamConfig.close();
                ret_error = tr("Error parsing %1 file").arg(strConfFileQt);
                return nullptr;
            }
        }
        lineCopy += line + "\n";
    }

    if (lineCopy.empty()) {
        lineCopy = "# Gamemaster config file\n"
                   "# Format: alias IP:port gamemasterprivkey collateral_output_txid collateral_output_index\n"
                   "# Example: gm1 127.0.0.2:49165 93HaYBVUCYjEMeeH1Y4sBGLALQZE1Yc1K64xiqgX37tGBDQL8Xg 2bcd3c84c84f87eaa86e4e56834c92927a07f9e18718810b92e0d0324456a67c 0"
                   "#";
    }
    lineCopy += "\n";

    streamConfig.close();

    std::string txID = collateralOut.hash.ToString();
    std::string indexOutStr = std::to_string(collateralOut.n);

    // Check IP address type
    QHostAddress hostAddress(QString::fromStdString(serviceAddr));
    QAbstractSocket::NetworkLayerProtocol layerProtocol = hostAddress.protocol();
    if (layerProtocol == QAbstractSocket::IPv6Protocol) {
        serviceAddr = "["+serviceAddr+"]";
    }

    fs::path pathConfigFile = AbsPathForConfigVal(fs::path("gamemaster_temp.conf"));
    FILE* configFile = fopen(pathConfigFile.string().c_str(), "w");
    lineCopy += alias+" "+serviceAddr+":"+port+" "+gmKeyString+" "+txID+" "+indexOutStr+"\n";
    fwrite(lineCopy.c_str(), std::strlen(lineCopy.c_str()), 1, configFile);
    fclose(configFile);

    fs::path pathOldConfFile = AbsPathForConfigVal(fs::path("old_gamemaster.conf"));
    if (fs::exists(pathOldConfFile)) {
        fs::remove(pathOldConfFile);
    }
    rename(pathGamemasterConfigFile, pathOldConfFile);

    fs::path pathNewConfFile = AbsPathForConfigVal(fs::path(strConfFile));
    rename(pathConfigFile, pathNewConfFile);

    auto ret_gm_entry = gamemasterConfig.add(alias, serviceAddr+":"+port, gmKeyString, gmPubKeyStr, txID, indexOutStr);

    // Lock collateral output
    walletModel->lockCoin(collateralOut.hash, collateralOut.n);
    return ret_gm_entry;
}

// Future: remove after v6.0
bool GMModel::removeLegacyGM(const std::string& alias_to_remove, const std::string& tx_id, unsigned int out_index, QString& ret_error)
{
    QString strConfFileQt(Hemis_GAMEMASTER_CONF_FILENAME);
    std::string strConfFile = strConfFileQt.toStdString();
    std::string strDataDir = GetDataDir().string();
    fs::path conf_file_path(strConfFile);
    if (strConfFile != conf_file_path.filename().string()) {
        throw std::runtime_error(strprintf(_("%s %s resides outside data directory %s"), strConfFile, strConfFile, strDataDir));
    }

    fs::path pathBootstrap = GetDataDir() / strConfFile;
    if (!fs::exists(pathBootstrap)) {
        ret_error = tr("%1 file doesn't exists").arg(strConfFileQt);
        return false;
    }

    fs::path pathGamemasterConfigFile = GetGamemasterConfigFile();
    fsbridge::ifstream streamConfig(pathGamemasterConfigFile);

    if (!streamConfig.good()) {
        ret_error = tr("Invalid %1 file").arg(strConfFileQt);
        return false;
    }

    int lineNumToRemove = -1;
    int linenumber = 1;
    std::string lineCopy;
    for (std::string line; std::getline(streamConfig, line); linenumber++) {
        if (line.empty()) continue;

        std::istringstream iss(line);
        std::string comment, alias, ip, privKey, txHash, outputIndex;

        if (iss >> comment) {
            if (comment.at(0) == '#') continue;
            iss.str(line);
            iss.clear();
        }

        if (!(iss >> alias >> ip >> privKey >> txHash >> outputIndex)) {
            iss.str(line);
            iss.clear();
            if (!(iss >> alias >> ip >> privKey >> txHash >> outputIndex)) {
                streamConfig.close();
                ret_error = tr("Error parsing %1 file").arg(strConfFileQt);
                return false;
            }
        }

        if (alias_to_remove == alias) {
            lineNumToRemove = linenumber;
        } else
            lineCopy += line + "\n";

    }

    if (lineCopy.empty()) {
        lineCopy = "# Gamemaster config file\n"
                   "# Format: alias IP:port gamemasterprivkey collateral_output_txid collateral_output_index\n"
                   "# Example: gm1 127.0.0.2:49165 93HaYBVUCYjEMeeH1Y4sBGLALQZE1Yc1K64xiqgX37tGBDQL8Xg 2bcd3c84c84f87eaa86e4e56834c92927a07f9e18718810b92e0d0324456a67c 0\n";
    }

    streamConfig.close();

    if (lineNumToRemove == -1) {
        ret_error = tr("GM alias %1 not found in %2 file").arg(QString::fromStdString(alias_to_remove)).arg(strConfFileQt);
        return false;
    }

    // Update file
    fs::path pathConfigFile = AbsPathForConfigVal(fs::path("gamemaster_temp.conf"));
    FILE* configFile = fsbridge::fopen(pathConfigFile, "w");
    fwrite(lineCopy.c_str(), std::strlen(lineCopy.c_str()), 1, configFile);
    fclose(configFile);

    fs::path pathOldConfFile = AbsPathForConfigVal(fs::path("old_gamemaster.conf"));
    if (fs::exists(pathOldConfFile)) {
        fs::remove(pathOldConfFile);
    }
    rename(pathGamemasterConfigFile, pathOldConfFile);

    fs::path pathNewConfFile = AbsPathForConfigVal(fs::path(strConfFile));
    rename(pathConfigFile, pathNewConfFile);

    // Unlock collateral
    walletModel->unlockCoin(uint256S(tx_id), out_index);
    // Remove alias
    gamemasterConfig.remove(alias_to_remove);
    return true;
}

void GMModel::setCoinControl(CCoinControl* coinControl)
{
    this->coinControl = coinControl;
}

void GMModel::resetCoinControl()
{
    coinControl = nullptr;
}