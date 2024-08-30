// Copyright (c) 2019-2022 The Hemis Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "qt/Hemis/gamemasterswidget.h"
#include "bls/bls_wrapper.h"
#include "coincontrol.h"
#include "qt/Hemis/forms/ui_gamemasterswidget.h"

#include "qt/Hemis/defaultdialog.h"
#include "qt/Hemis/qtutils.h"
#include "qt/Hemis/gmrow.h"
#include "qt/Hemis/gminfodialog.h"
#include "qt/Hemis/gamemasterwizarddialog.h"

#include "clientmodel.h"
#include "guiutil.h"
#include "interfaces/tiertwo.h"
#include "qt/Hemis/gmmodel.h"
#include "qt/Hemis/optionbutton.h"
#include "qt/walletmodel.h"
#include "uint256.h"

#define DECORATION_SIZE 65
#define NUM_ITEMS 3
#define REQUEST_START_ALL 1
#define REQUEST_START_MISSING 2

class GMHolder : public FurListRow<QWidget*>
{
public:
    explicit GMHolder(bool _isLightTheme) : FurListRow(), isLightTheme(_isLightTheme) {}

    GMRow* createHolder(int pos) override
    {
        if (!cachedRow) cachedRow = new GMRow();
        return cachedRow;
    }

    void init(QWidget* holder,const QModelIndex &index, bool isHovered, bool isSelected) const override
    {
        GMRow* row = static_cast<GMRow*>(holder);
        QString label = index.data(Qt::DisplayRole).toString();
        QString address = index.sibling(index.row(), GMModel::ADDRESS).data(Qt::DisplayRole).toString();
        QString status = index.sibling(index.row(), GMModel::STATUS).data(Qt::DisplayRole).toString();
        bool wasCollateralAccepted = index.sibling(index.row(), GMModel::WAS_COLLATERAL_ACCEPTED).data(Qt::DisplayRole).toBool();
        uint8_t type = index.sibling(index.row(), GMModel::TYPE).data(Qt::DisplayRole).toUInt();
        row->updateView("Address: " + address, label, status, wasCollateralAccepted, type);
    }

    QColor rectColor(bool isHovered, bool isSelected) override
    {
        return getRowColor(isLightTheme, isHovered, isSelected);
    }

    ~GMHolder() override{}

    bool isLightTheme;
    GMRow* cachedRow = nullptr;
};

GameMastersWidget::GameMastersWidget(HemisGUI *parent) :
    PWidget(parent),
    ui(new Ui::GameMastersWidget),
    isLoading(false)
{
    ui->setupUi(this);

    delegate = new FurAbstractListItemDelegate(
            DECORATION_SIZE,
            new GMHolder(isLightTheme()),
            this
    );

    this->setStyleSheet(parent->styleSheet());

    /* Containers */
    setCssProperty(ui->left, "container");
    ui->left->setContentsMargins(0,20,0,20);
    setCssProperty(ui->right, "container-right");
    ui->right->setContentsMargins(20,20,20,20);

    /* Light Font */
    QFont fontLight;
    fontLight.setWeight(QFont::Light);

    /* Title */
    setCssTitleScreen(ui->labelTitle);
    ui->labelTitle->setFont(fontLight);
    setCssSubtitleScreen(ui->labelSubtitle1);

    /* Buttons */
    setCssBtnPrimary(ui->pushButtonSave);
    setCssBtnPrimary(ui->pushButtonStartAll);
    setCssBtnPrimary(ui->pushButtonStartMissing);

    /* Coin control */
    this->coinControlDialog = new CoinControlDialog();

    /* Options */
    ui->btnCoinControl->setTitleClassAndText("btn-title-grey", "Coin Control");
    ui->btnCoinControl->setSubTitleClassAndText("text-subtitle", "Select the source of coins to create a Gamemaster");

    setCssProperty(ui->listGm, "container");
    ui->listGm->setItemDelegate(delegate);
    ui->listGm->setIconSize(QSize(DECORATION_SIZE, DECORATION_SIZE));
    ui->listGm->setMinimumHeight(NUM_ITEMS * (DECORATION_SIZE + 2));
    ui->listGm->setAttribute(Qt::WA_MacShowFocusRect, false);
    ui->listGm->setSelectionBehavior(QAbstractItemView::SelectRows);

    ui->emptyContainer->setVisible(false);
    setCssProperty(ui->pushImgEmpty, "img-empty-master");
    setCssProperty(ui->labelEmpty, "text-empty");

    connect(ui->pushButtonSave, &QPushButton::clicked, this, &GameMastersWidget::onCreateGMClicked);
    connect(ui->pushButtonStartAll, &QPushButton::clicked, [this]() {
        onStartAllClicked(REQUEST_START_ALL);
    });
    connect(ui->pushButtonStartMissing, &QPushButton::clicked, [this]() {
        onStartAllClicked(REQUEST_START_MISSING);
    });
    connect(ui->listGm, &QListView::clicked, this, &GameMastersWidget::onGMClicked);
    connect(ui->btnCoinControl, &OptionButton::clicked, this, &GameMastersWidget::onCoinControlClicked);
}

void GameMastersWidget::showEvent(QShowEvent *event)
{
    if (!gmModel) return;
    const auto& updateList = [&](){
        mnModel->updateGMList();
        updateListState();
    };
    updateList();

    if (!timer) {
        timer = new QTimer(this);
        connect(timer, &QTimer::timeout, updateList);
    }
    timer->start(30000);
}

void GameMastersWidget::hideEvent(QHideEvent *event)
{
    if (timer) timer->stop();
}

void GameMastersWidget::setGMModel(GMModel* _gmModel)
{
    gmModel = _gmModel;
    ui->listGm->setModel(gmModel);
    ui->listGm->setModelColumn(AddressTableModel::Label);
    updateListState();
}

void GameMastersWidget::updateListState()
{
    bool show = gmModel->rowCount() > 0;
    ui->listGm->setVisible(show);
    ui->emptyContainer->setVisible(!show);
    ui->pushButtonStartAll->setVisible(show);
}

void GameMastersWidget::onGMClicked(const QModelIndex& _index)
{
    ui->listGm->setCurrentIndex(_index);
    QRect rect = ui->listGm->visualRect(_index);
    QPoint pos = rect.topRight();
    pos.setX((int) pos.x() - (DECORATION_SIZE * 2));
    pos.setY((int) pos.y() + (DECORATION_SIZE * 1.5));
    if (!menu) {
        menu = new TooltipMenu(window, this);
        connect(menu, &TooltipMenu::message, this, &AddressesWidget::message);
        menu->addBtn(0, tr("Start"), [this](){onEditGMClicked();}); //TODO: change to UNBAN once 6.0 is out
        menu->addBtn(1, tr("Delete"), [this](){onDeleteGMClicked();});
        menu->addBtn(2, tr("Info"), [this](){onInfoGMClicked();});
        menu->adjustSize();

    } else {
        menu->hide();
    }
    index = _index;
    uint8_t gmType = index.sibling(index.row(), GMModel::TYPE).data(Qt::DisplayRole).toUInt();
    menu->showHideBtn(0, mnType == GMViewType::LEGACY);
    menu->move(pos);
    menu->show();

    // Back to regular status
    ui->listGm->scrollTo(index);
    ui->listGm->clearSelection();
    ui->listGm->setFocus();
}

bool GameMastersWidget::checkGMsNetwork()
{
    bool isTierTwoSync = gmModel->isGMsNetworkSynced();
    if (!isTierTwoSync) inform(tr("Please wait until the node is fully synced"));
    return isTierTwoSync;
}

void GameMastersWidget::onEditGMClicked()
{
    if (walletModel) {
        if (!walletModel->isRegTestNetwork() && !checkGMsNetwork()) return;
        uint8_t gmType = index.sibling(index.row(), GMModel::TYPE).data(Qt::DisplayRole).toUInt();
        if (gmType == GMViewType::LEGACY) {
            if (index.sibling(index.row(), GMModel::WAS_COLLATERAL_ACCEPTED).data(Qt::DisplayRole).toBool()) {
                // Start MN
                QString strAlias = this->index.data(Qt::DisplayRole).toString();
                if (ask(tr("Start Gamemaster"), tr("Are you sure you want to start gamemaster %1?\n").arg(strAlias))) {
                    WalletModel::UnlockContext ctx(walletModel->requestUnlock());
                    if (!ctx.isValid()) {
                        // Unlock wallet was cancelled
                        inform(tr("Cannot edit gamemaster, wallet locked"));
                        return;
                    }
                    startAlias(strAlias);
            }
        } else {
            inform(tr("Cannot start gamemaster, the collateral transaction has not been confirmed by the network yet.\n"
                    "Please wait few more minutes (gamemaster collaterals require %1 confirmations).").arg(gmModel->getGamemasterCollateralMinConf()));

        } else {
            // Deterministic
            bool isEnabled = index.sibling(index.row(), GMModel::IS_POSE_ENABLED).data(Qt::DisplayRole).toBool();
            if (isEnabled) {
                inform(tr("Cannot start an already started Gamemaster"));
            } else {
                uint256 proTxHash = uint256S(index.sibling(index.row(), GMModel::PRO_TX_HASH).data(Qt::DisplayRole).toString().toStdString());
                Optional<DGMData> opDGM = interfaces::g_tiertwo->getDGMData(proTxHash,
                    clientModel->getLastBlockIndexProcessed());
                if (!opDGM) {
                    inform(tr("Gamemaster not found"));
                } else {
                    std::string operatorKeyS = opDGM->operatorSk;
                    if (operatorKeyS.empty()) {
                        inform("Operator secret key not found");
                    } else {
                        Optional<CBLSSecretKey> operator_key = bls::DecodeSecret(Params(), operatorKeyS);
                        if (operator_key) {
                            std::string error_str = "";
                            if (!gmModel->unbanDGM(*operator_key, proTxHash, error_str)) {
                                inform(QString::fromStdString(error_str));
                            } else {
                                inform("Gamemaster successfully unbanned! Wait for the next minted block and it will update");
                            }
                        } else {
                            inform("Could not decode operator secret key");
                        }
                    }
                }
            }
        }
    }
}
void GameMastersWidget::startAlias(const QString& strAlias)
{
    QString strStatusHtml;
    strStatusHtml += "Alias: " + strAlias + " ";

    int failed_amount = 0;
    int success_amount = 0;
    std::string alias = strAlias.toStdString();
    std::string strError;
    gmModel->startAllLegacyGMs(false, failed_amount, success_amount, &alias, &strError);
    if (failed_amount > 0) {
        strStatusHtml = tr("failed to start.\nError: %1").arg(QString::fromStdString(strError));
    } else if (success_amount > 0) {
        strStatusHtml = tr("successfully started");
    }
    // update UI and notify
    updateModelAndInform(strStatusHtml);
}

void GameMastersWidget::updateModelAndInform(const QString& informText)
{
    gmModel->updateGMList();
    inform(informText);
}

void GameMastersWidget::onStartAllClicked(int type)
{
    if (!Params().IsRegTestNet() && !checkGMsNetwork()) return;     // skip on RegNet: so we can test even if tier two not synced

    if (isLoading) {
        inform(tr("Background task is being executed, please wait"));
    } else {
        std::unique_ptr<WalletModel::UnlockContext> pctx = std::make_unique<WalletModel::UnlockContext>(walletModel->requestUnlock());
        if (!pctx->isValid()) {
            warn(tr("Start ALL gamemasters failed"), tr("Wallet unlock cancelled"));
            return;
        }
        isLoading = true;
        if (!execute(type, std::move(pctx))) {
            isLoading = false;
            inform(tr("Cannot perform Gamemasters start"));
        }
    }
}

bool GameMastersWidget::startAll(QString& failText, bool onlyMissing)
{
    int amountOfGmFailed = 0;
    int amountOfGmStarted = 0;
    gmModel->startAllLegacyGMs(onlyMissing, amountOfGmFailed, amountOfGmStarted);
    if (amountOfGmFailed > 0) {
        failText = tr("%1 Gamemasters failed to start, %2 started").arg(amountOfGmFailed).arg(amountOfGmStarted);
        return false;
    }
    return true;
}

void GameMastersWidget::run(int type)
{
    bool isStartMissing = type == REQUEST_START_MISSING;
    if (type == REQUEST_START_ALL || isStartMissing) {
        QString failText;
        QString inform = startAll(failText, isStartMissing) ? tr("All Gamemasters started!") : failText;
        QMetaObject::invokeMethod(this, "updateModelAndInform", Qt::QueuedConnection,
                                  Q_ARG(QString, inform));
    }

    isLoading = false;
}

void GameMastersWidget::onError(QString error, int type)
{
    if (type == REQUEST_START_ALL) {
        QMetaObject::invokeMethod(this, "inform", Qt::QueuedConnection,
                                  Q_ARG(QString, "Error starting all Gamemasters"));
    }
}

void GameMastersWidget::onInfoGMClicked()
{
    WalletModel::UnlockContext ctx(walletModel->requestUnlock());
    if (!ctx.isValid()) {
        // Unlock wallet was cancelled
        inform(tr("Cannot show Gamemaster information, wallet locked"));
        return;
    }
    showHideOp(true);
    GmInfoDialog* dialog = new GmInfoDialog(window);
    QString label = index.data(Qt::DisplayRole).toString();
    QString address = index.sibling(index.row(), GMModel::ADDRESS).data(Qt::DisplayRole).toString();
    QString status = index.sibling(index.row(), GMModel::STATUS).data(Qt::DisplayRole).toString();
    QString txId = index.sibling(index.row(), GMModel::COLLATERAL_ID).data(Qt::DisplayRole).toString();
    QString outIndex = index.sibling(index.row(), GMModel::COLLATERAL_OUT_INDEX).data(Qt::DisplayRole).toString();
    QString pubKey = index.sibling(index.row(), GMModel::PUB_KEY).data(Qt::DisplayRole).toString();
    bool isLegacy = ((uint8_t) index.sibling(index.row(), GMModel::TYPE).data(Qt::DisplayRole).toUInt()) == GMViewType::LEGACY;
    Optional<DGMData> opDGM = nullopt;
    if (!isLegacy) {
        QString proTxHash = index.sibling(index.row(), GMModel::PRO_TX_HASH).data(Qt::DisplayRole).toString();
        opDGM = interfaces::g_tiertwo->getDGMData(uint256S(proTxHash.toStdString()),
                                                  clientModel->getLastBlockIndexProcessed());
    }
    dialog->setData(pubKey, label, address, txId, outIndex, status, opDGM);
    dialog->adjustSize();
    showDialog(dialog, 3, 17);    bool isLegacy = ((uint8_t) index.sibling(index.row(), MNModel::TYPE).data(Qt::DisplayRole).toUInt()) == MNViewType::LEGACY;
                                  Optional<DMNData> opDMN = nullopt;
                                  if (!isLegacy) {
                                      QString proTxHash = index.sibling(index.row(), MNModel::PRO_TX_HASH).data(Qt::DisplayRole).toString();
                                      opDMN = interfaces::g_tiertwo->getDMNData(uint256S(proTxHash.toStdString()),
                                                                                clientModel->getLastBlockIndexProcessed());
                                  }
                                  dialog->setData(pubKey, label, address, txId, outIndex, status, opDMN);
    if (dialog->exportGM) {
        QString legacyText = isLegacy ? tr(" Then start the Gamemaster using\nthis controller wallet (select the Gamemaster in the list and press \"start\").") : "";
        if (ask(tr("Remote Gamemaster Data"),
                tr("You are just about to export the required data to run a Gamemaster\non a remote server to your clipboard.\n\n\n"
                   "You will only have to paste the data in the Hemis.conf file\nof your remote server and start it."
                   "%1\n").arg(legacyText))) {
            // export data
            QString exportedGM = "gamemaster=1\n"
                                 "externalip=" + address.left(address.lastIndexOf(":")) + "\n"
                                 "listen=1\n";
            if (isLegacy) {
                exportedGM += "gamemasteraddr=" + address + +"\n" +
                             "gamemasterprivkey=" +
                             index.sibling(index.row(), GMModel::PRIV_KEY).data(Qt::DisplayRole).toString() + "\n";
            } else {
                exportedGM += "gmoperatorprivatekey=" + QString::fromStdString(opDGM->operatorSk.empty() ? "<insert operator private key here>" : opDGM->operatorSk) + "\n";
            }
            GUIUtil::setClipboard(exportedMN);
            inform(tr("Gamemaster data copied to the clipboard."));
        }
    }


    dialog->deleteLater();
}

void GameMastersWidget::onDeleteGMClicked()
{
    QString txId = index.sibling(index.row(), GMModel::COLLATERAL_ID).data(Qt::DisplayRole).toString();
    QString outIndex = index.sibling(index.row(), GMModel::COLLATERAL_OUT_INDEX).data(Qt::DisplayRole).toString();
    QString qAliasString = index.data(Qt::DisplayRole).toString();
    bool isLegacy = ((uint8_t) index.sibling(index.row(), GMModel::TYPE).data(Qt::DisplayRole).toUInt()) == GMViewType::LEGACY;

    bool convertOK = false;
    unsigned int indexOut = outIndex.toUInt(&convertOK);
    if (!convertOK) {
        inform(tr("Invalid collateral output index"));
        return;
    }

    if (isLegacy) {
        if (!ask(tr("Delete Gamemaster"), tr("You are just about to delete Gamemaster:\n%1\n\nAre you sure?").arg(qAliasString))) {
            return;
        }
        QString errorStr;
        if (!gmModel->removeLegacyGM(qAliasString.toStdString(), txId.toStdString(), indexOut, errorStr)) {
            inform(errorStr);
            return;
        }
        // Update list
        gmModel->removeGm(index);
        updateListState();
    } else {
        if (!ask(tr("Delete Gamemaster"), tr("You are just about to spend the collateral\n"
                                             "(creating a transaction to yourself)\n"
                                             "of your Gamemaster:\n\n%1\n\nAre you sure?")
            .arg(qAliasString))) {
            return;
        }

        auto res = gmModel->killDGM(uint256S(txId.toStdString()), indexOut);
        if (!res) {
            inform(QString::fromStdString(res.getError()));
            return;
        }
        inform("Deterministic Gamemaster removed successfully! the change will be reflected on the next mined block");
    }
}

void GameMastersWidget::onCreateGMClicked()
{
    WalletModel::UnlockContext ctx(walletModel->requestUnlock());
    if (!ctx.isValid()) {
        // Unlock wallet was cancelled
        inform(tr("Cannot create Gamemaster controller, wallet locked"));
        return;
    }

    CAmount gmCollateralAmount = gmModel->getGMCollateralRequiredAmount();
    if (walletModel->getBalance() <= gmCollateralAmount) {
        inform(tr("Not enough balance to create a gamemaster, %1 required.")
            .arg(GUIUtil::formatBalance(gmCollateralAmount, BitcoinUnits::HMS)));
        return;
    }

    if (coinControlDialog->coinControl && coinControlDialog->coinControl->HasSelected()) {
        std::vector<OutPointWrapper> coins;
        coinControlDialog->coinControl->ListSelected(coins);
        CAmount selectedBalance = 0;
        for (const auto& coin : coins) {
            selectedBalance += coin.value;
        }
        if (selectedBalance <= gmCollateralAmount) {
            inform(tr("Not enough coins selected to create a gamemaster, %1 required.")
                       .arg(GUIUtil::formatBalance(gmCollateralAmount, BitcoinUnits::HMS)));
            return;
        }
        gmModel->setCoinControl(coinControlDialog->coinControl);
    }

    GameMasterWizardDialog* dialog = new GameMasterDialog(walletModel, mnModel, clientModel, window);
    connect(dialog, &GameMasterWizardDialog::message, this, &PWidget::emitMessage);
    do {
        showHideOp(true);
        dialog->isWaitingForAsk = false;
        if (openDialogWithOpaqueBackgroundY(dialog, window, 5, 7)) {
            if (dialog->isOk) {
                updateListState();
                inform(dialog->returnStr);
            } else {
                warn(tr("Error creating gamemaster"), dialog->returnStr);
            }
        } else if (dialog->isWaitingForAsk) {
            auto* askDialog = new DefaultDialog(window);
            showHide(true);
            askDialog->setText(tr("Advanced Gamemaster Configurations"),
                            tr("The wallet can complete the next steps,\ncreating the GM keys and addresses automatically\n\n"
                               "Do you want to customize the owner, operator\nand voter or create them automatically?\n"
                               "(recommended only for advanced users)"),
                               tr("Automatic"), tr("Customize"));
            askDialog->adjustSize();
            openDialogWithOpaqueBackground(askDialog, window);
            askDialog->isOk ? dialog->completeTask() : dialog->moveToAdvancedConf();
        }
    } while (dialog->isWaitingForAsk);

    dialog->deleteLater();
    resetCoinControl();
}

void GameMastersWidget::changeTheme(bool isLightTheme, QString& theme)
{
    static_cast<GMHolder*>(this->delegate->getRowFactory())->isLightTheme = isLightTheme;
}

void GameMastersWidget::onCoinControlClicked()
{
    if (!coinControlDialog->hasModel()) coinControlDialog->setModel(walletModel);
    coinControlDialog->setSelectionType(true);
    coinControlDialog->refreshDialog();
    coinControlDialog->exec();
    ui->btnCoinControl->setActive(coinControlDialog->coinControl->HasSelected());
}

void GameMastersWidget::resetCoinControl()
{
    if (coinControlDialog) coinControlDialog->coinControl->SetNull();
    gmModel->resetCoinControl();
    ui->btnCoinControl->setActive(false);
}

GameMastersWidget::~GameMastersWidget()
{
    delete ui;
}
