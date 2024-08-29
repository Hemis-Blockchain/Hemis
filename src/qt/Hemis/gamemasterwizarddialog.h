// Copyright (c) 2019-2022 The Hemis Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef GAMEMASTERWIZARDDIALOG_H
#define GAMEMASTERWIZARDDIALOG_H

#include "qt/Hemis/focuseddialog.h"
#include "qt/Hemis/snackbar.h"
#include "gamemasterconfig.h"
#include "qt/Hemis/pwidget.h"

class ClientModel;
class ContactsDropdown;
class GMModel;
class QLineEdit;
class WalletModel;

namespace Ui {
class GameMasterWizardDialog;
class QPushButton;
}

struct GMSummary
{
    GMSummary(const std::string& _alias, const std::string& _service, const COutPoint& _collateralOut,
              const std::string& _ownerAddr, const std::string& _ownerPayoutAddr, const std::string& _operatorKey,
              const std::string& _votingKey, int _operatorPercentage,
              const Optional<std::string>& _operatorPayoutAddr) : alias(_alias), service(_service),
                                                            collateralOut(_collateralOut),
                                                            ownerAddr(_ownerAddr),
                                                            ownerPayoutAddr(_ownerPayoutAddr),
                                                            operatorKey(_operatorKey), votingKey(_votingKey),
                                                            operatorPercentage(_operatorPercentage),
                                                            operatorPayoutAddr(_operatorPayoutAddr) {}

    std::string alias;
    std::string service;
    COutPoint collateralOut;
    std::string ownerAddr;
    std::string ownerPayoutAddr;
    std::string operatorKey;
    std::string votingKey;
    int operatorPercentage{0};
    Optional<std::string> operatorPayoutAddr;
};

class GameMasterWizardDialog : public FocusedDialog, public PWidget::Translator
{
    Q_OBJECT

enum Pages {
   INTRO = 0,
   ALIAS = 1,
   SERVICE = 2,
   OWNER = 3,
   OPERATOR = 4,
   VOTER = 5,
   SUMMARY = 6
};

public:
    explicit GameMasterWizardDialog(WalletModel* walletMode,
                                    GMModel* gmModel,
                                    ClientModel* clientModel,
                                    QWidget *parent = nullptr);
    ~GameMasterWizardDialog() override;
    void showEvent(QShowEvent *event) override;
    QString translate(const char *msg) override { return tr(msg); }

    void moveToAdvancedConf()
    {
        pos = Pages::OWNER;
        moveToNextPage(Pages::SERVICE, pos);
    };

    void completeTask();

    QString returnStr{""};
    bool isOk{false};
    bool isWaitingForAsk{false};
    CGamemasterConfig::CGamemasterEntry* gmEntry{nullptr};

Q_SIGNALS:
    void message(const QString& title, const QString& body, unsigned int style, bool* ret = nullptr);

private Q_SLOTS:
    void accept() override;
    void onBackClicked();
private:
    Ui::GameMasterWizardDialog *ui;
    ContactsDropdown* dropdownMenu{nullptr};
    QAction* actOwnerAddrList{nullptr};

    QList<QPushButton*> list_icConfirm{};
    QList<QPushButton*> list_pushNumber{};
    QList<QPushButton*> list_pushName{};
    SnackBar* snackBar{nullptr};
    int pos = 0;
    std::unique_ptr<GMSummary> gmSummary{nullptr};
    bool isDeterministic{false};

    WalletModel* walletModel{nullptr};
    GMModel* gmModel{nullptr};
    ClientModel* clientModel{nullptr};

    void initIntroPage(const QString& collateralAmountStr);
    void initCollateralPage(const QString& collateralAmountStr);
    void initServicePage();
    void initOwnerPage();
    void initOperatorPage();
    void initVoterPage();
    void initSummaryPage();

    bool createGM();
    void setSummary();
    void inform(const QString& text);
    bool errorOut(const QString& err);

    void moveToNextPage(int currentPos, int nextPos);
    void moveBack(int backPos);

    bool validateService();
    bool validateVoter();
    bool validateOwner();
    bool validateOperator();

    CallResult<std::pair<std::string, CKeyID>> getOrCreateOwnerAddress(const std::string& alias);
    CallResult<std::pair<std::string, CKeyID>> getOrCreatePayoutAddress(const std::string& alias);
    CallResult<std::pair<std::string, CKeyID>> getOrCreateVotingAddress(const std::string& alias);

    void setDropdownList(QLineEdit* edit, QAction* action, const QStringList& types);
    void onAddrListClicked(const QStringList& types, QLineEdit* edit);
};

#endif // GAMEMASTERWIZARDDIALOG_H
