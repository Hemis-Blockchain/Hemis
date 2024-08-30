// Copyright (c) 2019-2021 The Hemis Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "qt/Hemis/gmrow.h"
#include "qt/Hemis/forms/ui_gmrow.h"
#include "qt/Hemis/qtutils.h"
#include "qt/Hemis/gmmodel.h"

GMRow::GMRow(QWidget *parent) :
    QWidget(parent),
    ui(new Ui::GMRow)
{
    ui->setupUi(this);
    setCssProperty(ui->labelAddress, "text-list-body2");
    setCssProperty(ui->labelName, "text-list-title1");
    setCssProperty(ui->labelDate, "text-list-caption-medium");
    ui->lblDivisory->setStyleSheet("background-color:#bababa;");
}

void GMRow::updateView(QString address,
                       const QString& label,
                       QString status,
                       bool wasCollateralAccepted,
                       uint8_t type)
{
    ui->labelName->setText(label);
    address = address.size() < 40 ? address : address.left(20) + "..." + address.right(20);
    ui->labelAddress->setText(address);
    if (!wasCollateralAccepted) status = tr("Collateral tx not found");
    ui->labelDate->setText(tr("Status: %1").arg(status));
    ui->btnIcon->setIcon(QIcon(type == GMViewType::LEGACY ? "://ic-lgm" : "://ic-dgm"));
}

GMRow::~GMRow()
{
    delete ui;
}
