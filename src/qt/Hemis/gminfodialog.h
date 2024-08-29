// Copyright (c) 2019-2021 The Hemis Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef GMINFODIALOG_H
#define GMINFODIALOG_H

#include "qt/Hemis/focuseddialog.h"
#include "qt/Hemis/snackbar.h"

#include "interfaces/tiertwo.h"
#include "optional.h"

class WalletModel;

namespace Ui {
class GmInfoDialog;
}

class GmInfoDialog : public FocusedDialog
{
    Q_OBJECT

public:
    explicit GmInfoDialog(QWidget *parent = nullptr);
    ~GmInfoDialog() override;

    bool exportGM = false;

    void setData(const QString& _pubKey,
                 const QString& name,
                 const QString& address,
                 const QString& _txId,
                 const QString& outputIndex,
                 const QString& status,
                 const Optional<DGMData>& dgmData);
public Q_SLOTS:
    void reject() override;

private:
    Ui::GmInfoDialog *ui;
    SnackBar *snackBar = nullptr;
    int nDisplayUnit = 0;
    WalletModel *model = nullptr;
    QString txId;
    QString pubKey;
    Optional<DGMData> dgmData{nullopt};

    void copyInform(const QString& copyStr, const QString& message);
    void setDGMDataVisible(bool show);
};

#endif // GMINFODIALOG_H
