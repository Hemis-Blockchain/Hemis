// Copyright (c) 2019-2022 The Hemis Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php.

#include "qt/Hemis/settings/settingsinformationwidget.h"
#include "qt/Hemis/settings/forms/ui_settingsinformationwidget.h"

#include "clientmodel.h"
#include "chainparams.h"
#include "db.h"
#include "util/system.h"
#include "guiutil.h"
#include "qt/Hemis/qtutils.h"

#include <QDir>

#define REQUEST_UPDATE_COUNTS 0

SettingsInformationWidget::SettingsInformationWidget(HemisGUI* _window,QWidget *parent) :
    PWidget(_window,parent),
    ui(new Ui::SettingsInformationWidget)
{
    ui->setupUi(this);

    this->setStyleSheet(parent->styleSheet());

    // Containers
    setCssProperty(ui->left, "container");
    ui->left->setContentsMargins(10,10,10,10);
    setCssProperty({ui->layoutOptions1, ui->layoutOptions2, ui->layoutOptions3}, "container-options");

    // Title
    setCssTitleScreen(ui->labelTitle);

    setCssProperty({
        ui->labelTitleDataDir,
        ui->labelTitleBerkeley,
        ui->labelTitleAgent,
        ui->labelTitleClient,
        ui->labelTitleTime,
        ui->labelTitleName,
        ui->labelTitleConnections,
        ui->labelTitleGamemasters,
        ui->labelTitleBlockNumber,
        ui->labelTitleBlockTime,
        ui->labelTitleBlockHash,
        ui->labelTitleNumberTransactions,
        ui->labelInfoNumberTransactions,
        ui->labelInfoClient,
        ui->labelInfoAgent,
        ui->labelInfoBerkeley,
        ui->labelInfoDataDir,
        ui->labelInfoTime,
        ui->labelInfoConnections,
        ui->labelInfoGamemasters,
        ui->labelInfoBlockNumber
        }, "text-main-settings");

    setCssProperty({
        ui->labelTitleGeneral,
        ui->labelTitleNetwork,
        ui->labelTitleBlockchain,
        ui->labelTitleMemory,

    },"text-title");

    // TODO: Mempool section is not currently implemented and instead, hidden for now
    ui->labelTitleMemory->setVisible(false);
    ui->labelTitleNumberTransactions->setVisible(false);
    ui->labelInfoNumberTransactions->setText("0");
    ui->labelInfoNumberTransactions->setVisible(false);

    // Information Network
    ui->labelInfoName->setText(tr("Main"));
    ui->labelInfoName->setProperty("cssClass", "text-main-settings");
    ui->labelInfoConnections->setText("0 (In: 0 / Out: 0)");
    ui->labelInfoGamemasters->setText("Total: 0 (IPv4: 0 / IPv6: 0 / Tor: 0 / Unknown: 0");

    // Information Blockchain
    ui->labelInfoBlockNumber->setText("0");
    ui->labelInfoBlockTime->setText("Sept 6, 2018. Thursday, 8:21:49 PM");
    ui->labelInfoBlockTime->setProperty("cssClass", "text-main-grey");
    ui->labelInfoBlockHash->setProperty("cssClass", "text-main-hash");

    // Buttons
    setCssBtnSecondary(ui->pushButtonBackups);
    setCssBtnSecondary(ui->pushButtonFile);
    setCssBtnSecondary(ui->pushButtonNetworkMonitor);

    // Data
#ifdef ENABLE_WALLET
    // Wallet data -- remove it with if it's needed
    ui->labelInfoBerkeley->setText(DbEnv::version(0, 0, 0));
#else
    ui->labelInfoBerkeley->setText(tr("No information"));
#endif

    connect(ui->pushButtonBackups, &QPushButton::clicked, [this](){
        if (!GUIUtil::showBackups())
            inform(tr("Unable to open backups folder"));
    });
    connect(ui->pushButtonFile, &QPushButton::clicked, [this](){
        if (!GUIUtil::openConfigfile())
            inform(tr("Unable to open Hemis.conf with default application"));
    });
    connect(ui->pushButtonNetworkMonitor, &QPushButton::clicked, this, &SettingsInformationWidget::openNetworkMonitor);
}


void SettingsInformationWidget::loadClientModel()
{
    if (clientModel && clientModel->getPeerTableModel() && clientModel->getBanTableModel()) {
        // Provide initial values
        ui->labelInfoClient->setText(clientModel->formatFullVersion());
        ui->labelInfoAgent->setText(clientModel->clientName());
        ui->labelInfoTime->setText(clientModel->formatClientStartupTime());
        ui->labelInfoName->setText(QString::fromStdString(Params().NetworkIDString()));
        ui->labelInfoDataDir->setText(clientModel->dataDir());

        setNumConnections(clientModel->getNumConnections());
        connect(clientModel, &ClientModel::numConnectionsChanged, this, &SettingsInformationWidget::setNumConnections);
        connect(clientModel, &ClientModel::networkActiveChanged, this, &SettingsInformationWidget::networkActiveChanged);

        setNumBlocks(clientModel->getNumBlocks());
        connect(clientModel, &ClientModel::numBlocksChanged, this, &SettingsInformationWidget::setNumBlocks);

        connect(clientModel, &ClientModel::strGamemastersChanged, this, &SettingsInformationWidget::setGamemasterCount);
    }
}

void SettingsInformationWidget::updateNetworkState(int numConnections)
{
    bool netActivityState = clientModel->getNetworkActive();

    QString connections;
    if (!netActivityState && numConnections == 0) {
        connections = tr("Network activity disabled");
    } else {
        connections = QString::number(numConnections) + " (";
        connections += tr("In:") + " " + QString::number(clientModel->getNumConnections(CONNECTIONS_IN)) + " / ";
        connections += tr("Out:") + " " + QString::number(clientModel->getNumConnections(CONNECTIONS_OUT)) + ")";
        if(!netActivityState) {
            connections += " " + tr("Network activity disabled");
        }
    }
    ui->labelInfoConnections->setText(connections);
}

void SettingsInformationWidget::setNumConnections(int count)
{
    if (!clientModel)
        return;
    updateNetworkState(count);
}

void SettingsInformationWidget::networkActiveChanged(bool active)
{
    updateNetworkState(clientModel->getNumConnections());
}

void SettingsInformationWidget::setNumBlocks(int count)
{
    if (!isVisible()) return;
    ui->labelInfoBlockNumber->setText(QString::number(count));
    if (clientModel) {
        ui->labelInfoBlockTime->setText(clientModel->getLastBlockDate().toString());
        ui->labelInfoBlockHash->setText(clientModel->getLastBlockHash());
    }
}

void SettingsInformationWidget::setGamemasterCount(const QString& strGamemasters)
{
    ui->labelInfoGamemasters->setText(strGamemasters);
}

void SettingsInformationWidget::openNetworkMonitor()
{
    if (!rpcConsole) {
        rpcConsole = new RPCConsole(nullptr);
        rpcConsole->setClientModel(clientModel);
        rpcConsole->setWalletModel(walletModel);
    }
    rpcConsole->showNetwork();
}

void SettingsInformationWidget::showEvent(QShowEvent *event)
{
    QWidget::showEvent(event);
    if (clientModel) {
        clientModel->startGamemastersTimer();
        // Initial gamemasters count value, running in a worker thread to not lock gmmanager mutex in the main thread.
        execute(REQUEST_UPDATE_COUNTS);
    }
}

void SettingsInformationWidget::hideEvent(QHideEvent *event) {
    QWidget::hideEvent(event);
    if (clientModel) {
        clientModel->stopGamemastersTimer();
    }
}

void SettingsInformationWidget::run(int type)
{
    if (type == REQUEST_UPDATE_COUNTS) {
        QMetaObject::invokeMethod(this, "setGamemasterCount",
                                  Qt::QueuedConnection, Q_ARG(QString, clientModel->getGamemastersCountString()));
        QMetaObject::invokeMethod(this, "setNumBlocks",
                                  Qt::QueuedConnection, Q_ARG(int, clientModel->getLastBlockProcessedHeight()));
    }
}

void SettingsInformationWidget::onError(QString error, int type)
{
    if (type == REQUEST_UPDATE_COUNTS) {
        setGamemasterCount(tr("No available data"));
    }
}

SettingsInformationWidget::~SettingsInformationWidget()
{
    delete ui;
}
