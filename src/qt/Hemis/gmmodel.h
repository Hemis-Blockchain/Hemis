// Copyright (c) 2019-2022 The Hemis Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef GMMODEL_H
#define GMMODEL_H

#include <QAbstractTableModel>
#include "amount.h"
#include "gamemasterconfig.h"
#include "operationresult.h"
#include "primitives/transaction.h"
#include "bls/key_io.h"
#include "uint256.h"
#include "wallet/wallet.h" // TODO: Move to walletModel
#include "qt/walletmodel.h"

class CGamemaster;
class DGMView;
class WalletModel;

enum GMViewType : uint8_t
{
    LEGACY = 0,
    DGM_OWNER = (1 << 0),
    DGM_OPERATOR = (1 << 1),
    DGM_VOTER = (1 << 2)
};

class GamemasterWrapper
{
public:
    explicit GamemasterWrapper(
            const QString& _label,
            const QString& _ipPortStr,
            CGamemaster* _gamemaster,
            COutPoint& _collateralId,
            const Optional<QString>& _gmPubKey,
            const std::shared_ptr<DGMView>& _dgmView) :
            label(_label), ipPort(_ipPortStr), gamemaster(_gamemaster),
            collateralId(_collateralId), gmPubKey(_gmPubKey), dgmView(_dgmView) { };

    QString label;
    QString ipPort;
    CGamemaster* gamemaster{nullptr};
    // Cache collateral id and MN pk to be used if 'gamemaster' is null.
    // (Denoting GMs that were not initialized on the conf file or removed from the network list)
    // when gamemaster is not null, the collateralId is directly pointing to gamemaster.vin.prevout.
    Optional<COutPoint> collateralId{nullopt};
    Optional<QString> gmPubKey{nullopt};

    // DGM data
    std::shared_ptr<DGMView> dgmView{nullptr};

    uint16_t getType() const;
};

class GMModel : public QAbstractTableModel
{
    Q_OBJECT

public:
    explicit GMModel(QObject *parent);
    ~GMModel() override {
        nodes.clear();
        collateralTxAccepted.clear();
    }
    void init();
    void setWalletModel(WalletModel* _model) { walletModel = _model; };

    enum ColumnIndex {
        ALIAS = 0,  /**< User specified GM alias */
        ADDRESS = 1, /**< Node address */
        PROTO_VERSION = 2, /**< Node protocol version */
        STATUS = 3, /**< Node status */
        ACTIVE_TIMESTAMP = 4, /**<  */
        PUB_KEY = 5,
        COLLATERAL_ID = 6,
        COLLATERAL_OUT_INDEX = 7,
        PRIV_KEY = 8,
        WAS_COLLATERAL_ACCEPTED = 9,
        TYPE = 10, /**< Whether is from a Legacy or Deterministic GM */
        IS_POSE_ENABLED = 11, /**< Whether the DGM is enabled or not*/
        PRO_TX_HASH = 12, /**< The DGM pro reg hash */
        COLUMN_COUNT
    };

    int rowCount(const QModelIndex &parent = QModelIndex()) const override;
    int columnCount(const QModelIndex &parent = QModelIndex()) const override;
    QVariant data(const QModelIndex &index, int role = Qt::DisplayRole) const override;
    bool removeGm(const QModelIndex& index);
    bool addGm(CGamemasterConfig::CGamemasterEntry* entry);
    void updateGMList();
    // Whether the MN legacy system is active or not
    bool isLegacySystemObsolete();
    // Whether the tier two synchronization completed or not

    bool isGMsNetworkSynced();
    // Returns the GM activeState field.
    int getGMState(const QString& gmAlias);
    // Checks if the gamemaster is inactive
    bool isGMInactive(const QString& gmAlias);
    // Gamemaster is active if it's in PRE_ENABLED OR ENABLED state
    bool isGMActive(const QString& gmAlias);
    // Gamemaster collateral has enough confirmations
    bool isGMCollateralMature(const QString& gmAlias);
    // Validate string representing a gamemaster IP address
    static bool validateGMIP(const QString& addrStr);

    // Return the specific chain amount value for the GM collateral output.
    CAmount getGMCollateralRequiredAmount();
    // Return the specific chain min conf for the collateral tx
    int getGamemasterCollateralMinConf();

    // Creates the DGM and return the hash of the proregtx
    CallResult<uint256> createDGM(const std::string& alias,
                                  const Optional<COutPoint>& collateral,
                                  const Optional<QString>& addr_label,
                                  std::string& serviceAddr,
                                  const std::string& servicePort,
                                  const CKeyID& ownerAddr,
                                  const Optional<std::string>& operatorPubKey,
                                  const Optional<CKeyID>& votingAddr,
                                  const CKeyID& payoutAddr,
                                  std::string& strError,
                                  const Optional<uint16_t>& operatorPercentage = nullopt,
                                  const Optional<CKeyID>& operatorPayoutAddr = nullopt);

    // Completely stops the Gamemaster spending the collateral
    OperationResult killDGM(const uint256& collateralHash, unsigned int outIndex);

    //Unban a Pose-banned DGM
    bool unbanDGM(CBLSSecretKey& operatorKey,uint256 proTxHash, std::string& strError);
    // Generates the collateral transaction
    bool createDGMExternalCollateral(const QString& alias, const QString& addr, COutPoint& ret_outpoint, QString& ret_error);
    bool createDGMInternalCollateral(const QString& alias, const QString& addr, CTransactionRef& ret_tx,COutPoint& ret_outpoint, QString& ret_error,int nExtraSize=0);
    // Creates the gmb and broadcast it to the network
    bool startLegacyGM(const CGamemasterConfig::CGamemasterEntry& gme, int chainHeight, std::string& strError);
    void startAllLegacyGMs(bool onlyMissing, int& amountOfGmFailed, int& amountOfGmStarted,
                           std::string* aliasFilter = nullptr, std::string* error_ret = nullptr);

    CGamemasterConfig::CGamemasterEntry* createLegacyGM(COutPoint& collateralOut,
                                                        const std::string& alias,
                                                        std::string& serviceAddr,
                                                        const std::string& port,
                                                        const std::string& gmKeyString,
                                                        const std::string& _gmPubKeyStr,
                                                        QString& ret_error);

    bool removeLegacyGM(const std::string& alias_to_remove, const std::string& tx_id, unsigned int out_index, QString& ret_error);
    void setCoinControl(CCoinControl* coinControl);
    void resetCoinControl();

private:
    CCoinControl* coinControl;
    // alias gm node ---> pair <ip, master node>
    WalletModel* walletModel{nullptr};
    // alias mn node ---> <ip, master node>
    QList<GamemasterWrapper> nodes;
    QMap<std::string, bool> collateralTxAccepted;

    const GamemasterWrapper* getGMWrapper(const QString& gmAlias);
    CallResult<uint256> createDGMInternal(const Optional<COutPoint>& collateral,
                                             const Optional<QString>& addr_label,
                                             const Optional<CKey>& keyCollateral,
                                             const CService& service,
                                             const CKeyID& ownerAddr,
                                             const CBLSPublicKey& operatorPubKey,
                                             const Optional<CKeyID>& votingAddr,
                                             const CKeyID& payoutAddr,
                                             const Optional<CBLSSecretKey>& operatorSk,
                                             const Optional<uint16_t>& operatorPercentage,
                                             const Optional<CKeyID>& operatorPayoutAddr);
};

#endif // GMMODEL_H
