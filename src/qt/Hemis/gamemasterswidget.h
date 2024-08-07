// Copyright (c) 2019-2022 The Hemis Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef GAMEMASTERSWIDGET_H
#define GAMEMASTERSWIDGET_H

#include "coincontroldialog.h"
#include "qt/Hemis/furabstractlistitemdelegate.h"
#include "qt/Hemis/pwidget.h"
#include "qt/Hemis/tooltipmenu.h"

#include <atomic>

#include <QTimer>
#include <QWidget>

class HemisGUI;
class GMModel;

namespace Ui {
class GameMastersWidget;
}

QT_BEGIN_NAMESPACE
class QModelIndex;
QT_END_NAMESPACE

class GameMastersWidget : public PWidget
{
    Q_OBJECT

public:

    explicit GameMastersWidget(HemisGUI *parent = nullptr);
    ~GameMastersWidget();
    void resetCoinControl();
    void setGMModel(GMModel* _gmModel);

    void run(int type) override;
    void onError(QString error, int type) override;

    void showEvent(QShowEvent *event) override;
    void hideEvent(QHideEvent *event) override;

private Q_SLOTS:
    void onCoinControlClicked();
    void onCreateGMClicked();
    void onStartAllClicked(int type);
    void changeTheme(bool isLightTheme, QString &theme) override;
    void onGMClicked(const QModelIndex &index);
    void onEditGMClicked();
    void onDeleteGMClicked();
    void onInfoGMClicked();
    void updateListState();
    void updateModelAndInform(const QString& informText);

private:
    Ui::GameMastersWidget *ui;
    FurAbstractListItemDelegate *delegate;
    GMModel *gmModel = nullptr;
    TooltipMenu* menu = nullptr;
    QModelIndex index;
    QTimer *timer = nullptr;
    CoinControlDialog* coinControlDialog = nullptr;

    std::atomic<bool> isLoading;

    bool checkGMsNetwork();
    void startAlias(const QString& strAlias);
    bool startAll(QString& failedGM, bool onlyMissing);
};

#endif // GAMEMASTERSWIDGET_H
