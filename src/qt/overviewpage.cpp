// Copyright (c) 2011-2013 The Atdollar developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "overviewpage.h"
#include "ui_overviewpage.h"

#include "bitcoinunits.h"
#include "clientmodel.h"
#include "guiconstants.h"
#include "guiutil.h"
#include "optionsmodel.h"
#include "transactionfilterproxy.h"
#include "transactiontablemodel.h"
#include "walletmodel.h"

#include "rpcconsole.h"

#include "main.h"
#include "chainparams.h"
#include "rpcserver.h"
#include "rpcclient.h"
#include "util.h"

#include "json/json_spirit_value.h"

#include <openssl/crypto.h>

#include <QKeyEvent>
#include <QScrollBar>
#include <QThread>
#include <QTime>
#include <QMessageBox>
#include <QTimer>

#if QT_VERSION < 0x050000
#include <QUrl>
#endif

#include <QAbstractItemDelegate>
#include <QPainter>

#define DECORATION_SIZE 64
#define NUM_ITEMS 3
std::string str_g;
class TxViewDelegate : public QAbstractItemDelegate
{
    Q_OBJECT
public:
    TxViewDelegate(): QAbstractItemDelegate(), unit(BitcoinUnits::EWK)
    {

    }

    inline void paint(QPainter *painter, const QStyleOptionViewItem &option,
                      const QModelIndex &index ) const
    {
        painter->save();

        QIcon icon = qvariant_cast<QIcon>(index.data(Qt::DecorationRole));
        QRect mainRect = option.rect;
        QRect decorationRect(mainRect.topLeft(), QSize(DECORATION_SIZE, DECORATION_SIZE));
        int xspace = DECORATION_SIZE + 8;
        int ypad = 6;
        int halfheight = (mainRect.height() - 2*ypad)/2;
        QRect amountRect(mainRect.left() + xspace, mainRect.top()+ypad, mainRect.width() - xspace, halfheight);
        QRect addressRect(mainRect.left() + xspace, mainRect.top()+ypad+halfheight, mainRect.width() - xspace, halfheight);
        icon.paint(painter, decorationRect);

        QDateTime date = index.data(TransactionTableModel::DateRole).toDateTime();
        QString address = index.data(Qt::DisplayRole).toString();
        qint64 amount = index.data(TransactionTableModel::AmountRole).toLongLong();
        bool confirmed = index.data(TransactionTableModel::ConfirmedRole).toBool();
        QVariant value = index.data(Qt::ForegroundRole);
        QColor foreground = option.palette.color(QPalette::Text);
        if(value.canConvert<QBrush>())
        {
            QBrush brush = qvariant_cast<QBrush>(value);
            foreground = brush.color();
        }

        painter->setPen(foreground);
        QRect boundingRect;
        painter->drawText(addressRect, Qt::AlignLeft|Qt::AlignVCenter, address, &boundingRect);

        if (index.data(TransactionTableModel::WatchonlyRole).toBool())
        {
            QIcon iconWatchonly = qvariant_cast<QIcon>(index.data(TransactionTableModel::WatchonlyDecorationRole));
            QRect watchonlyRect(boundingRect.right() + 5, mainRect.top()+ypad+halfheight, 16, halfheight);
            iconWatchonly.paint(painter, watchonlyRect);
        }

        if(amount < 0)
        {
            foreground = COLOR_NEGATIVE;
        }
        else if(!confirmed)
        {
            foreground = COLOR_UNCONFIRMED;
        }
        else
        {
            foreground = option.palette.color(QPalette::Text);
        }
        painter->setPen(foreground);
        QString amountText = BitcoinUnits::formatWithUnit(unit, amount, true, BitcoinUnits::separatorAlways);
        if(!confirmed)
        {
            amountText = QString("[") + amountText + QString("]");
        }
        painter->drawText(amountRect, Qt::AlignRight|Qt::AlignVCenter, amountText);

        painter->setPen(option.palette.color(QPalette::Text));
        painter->drawText(amountRect, Qt::AlignLeft|Qt::AlignVCenter, GUIUtil::dateTimeStr(date));

        painter->restore();
    }

    inline QSize sizeHint(const QStyleOptionViewItem &option, const QModelIndex &index) const
    {
        return QSize(DECORATION_SIZE, DECORATION_SIZE);
    }

    int unit;

};
#include "overviewpage.moc"

OverviewPage::OverviewPage(QWidget *parent) :
    QWidget(parent),
    ui(new Ui::OverviewPage),
    clientModel(0),
    walletModel(0),
    currentBalance(-1),
    currentUnconfirmedBalance(-1),
    currentImmatureBalance(-1),
    currentWatchOnlyBalance(-1),
    currentWatchUnconfBalance(-1),
    currentWatchImmatureBalance(-1),
    txdelegate(new TxViewDelegate()),
    filter(0)
{
    str_g = "";
    timer = new QTimer(this);
    connect(timer,SIGNAL(timeout()),this,SLOT(timerUpDate()));

    ui->setupUi(this);
    timer->start(1000);

    // Recent transactions
    ui->listTransactions->setItemDelegate(txdelegate);
    ui->listTransactions->setIconSize(QSize(DECORATION_SIZE, DECORATION_SIZE));
    ui->listTransactions->setMinimumHeight(NUM_ITEMS * (DECORATION_SIZE + 2));
    ui->listTransactions->setAttribute(Qt::WA_MacShowFocusRect, false);

    connect(ui->listTransactions, SIGNAL(clicked(QModelIndex)), this, SLOT(handleTransactionClicked(QModelIndex)));

    connect(ui->fullmining, SIGNAL(clicked()), this, SLOT(fullspeed()));
    connect(ui->halfmining, SIGNAL(clicked()), this, SLOT(halfspeed()));
    connect(ui->stopmining, SIGNAL(clicked()), this, SLOT(zerospeed()));

    // init "out of sync" warning labels
    ui->labelWalletStatus->setText("(" + tr("out of sync") + ")");
    ui->labelTransactionsStatus->setText("(" + tr("out of sync") + ")");
    ui->miningstatus->setText("(" + tr("stop") + ")");
    // start with displaying the "out of sync" warnings
    showOutOfSyncWarning(true);
}

void OverviewPage::timerUpDate()
{
    request(QString("getgenerate"));
    if(str_g == "true")
    {
        ui->miningstatus->setText("(" + tr("Mining...") + ")");
    }
    else
    {
        ui->miningstatus->setText("(" + tr("Stoped") + ")");
    }
    timer->start(1000);
}

void OverviewPage::handleTransactionClicked(const QModelIndex &index)
{
    if(filter)
        emit transactionClicked(filter->mapToSource(index));
}

void OverviewPage::fullspeed()
{
    QString questionString = tr("The minging process will use 100% of your CPU");

    QMessageBox::StandardButton retval = QMessageBox::question(this, tr("Start Mining"),
                                                               questionString,
                                                               QMessageBox::Yes | QMessageBox::Cancel,
                                                               QMessageBox::Cancel);

    if(retval == QMessageBox::Cancel)
    {
        return;
    }
    request(QString("setgenerate true"));
}

void OverviewPage::halfspeed()
{
    QString questionString = tr("The minging process will use 50% of your CPU");

    QMessageBox::StandardButton retval = QMessageBox::question(this, tr("Start Mining"),
                                                               questionString,
                                                               QMessageBox::Yes | QMessageBox::Cancel,
                                                               QMessageBox::Cancel);

    if(retval == QMessageBox::Cancel)
    {
        return;
    }
    request(QString("setgenerate true 1"));
}

void OverviewPage::zerospeed()
{
    if (str_g == "true")
    {
        QString questionString = tr("Are you sure want to stop mining");

        QMessageBox::StandardButton retval = QMessageBox::question(this, tr("Stop Mining"),
                                                                   questionString,
                                                                   QMessageBox::Yes | QMessageBox::Cancel,
                                                                   QMessageBox::Cancel);

        if(retval == QMessageBox::Cancel)
        {
            return;
        }
         request(QString("setgenerate false"));
    }
    else
    {
        QString questionString = tr("No mining process have started yet");

        QMessageBox::StandardButton retval = QMessageBox::question(this, tr("Error"),
                                                                   questionString,
                                                                   QMessageBox::Yes | QMessageBox::Cancel,
                                                                   QMessageBox::Cancel);
        if(retval == QMessageBox::Yes)
        {
            return;
        }
    }

}

OverviewPage::~OverviewPage()
{
    delete ui;
}

void OverviewPage::setBalance(const CAmount& balance, const CAmount& unconfirmedBalance, const CAmount& immatureBalance, const CAmount& watchOnlyBalance, const CAmount& watchUnconfBalance, const CAmount& watchImmatureBalance)
{
    int unit = walletModel->getOptionsModel()->getDisplayUnit();
    currentBalance = balance;
    currentUnconfirmedBalance = unconfirmedBalance;
    currentImmatureBalance = immatureBalance;
    currentWatchOnlyBalance = watchOnlyBalance;
    currentWatchUnconfBalance = watchUnconfBalance;
    currentWatchImmatureBalance = watchImmatureBalance;
    ui->labelBalance->setText(BitcoinUnits::formatWithUnit(unit, balance, false, BitcoinUnits::separatorAlways));
    ui->labelUnconfirmed->setText(BitcoinUnits::formatWithUnit(unit, unconfirmedBalance, false, BitcoinUnits::separatorAlways));
    ui->labelImmature->setText(BitcoinUnits::formatWithUnit(unit, immatureBalance, false, BitcoinUnits::separatorAlways));
    ui->labelTotal->setText(BitcoinUnits::formatWithUnit(unit, balance + unconfirmedBalance + immatureBalance, false, BitcoinUnits::separatorAlways));
    ui->labelWatchAvailable->setText(BitcoinUnits::formatWithUnit(unit, watchOnlyBalance, false, BitcoinUnits::separatorAlways));
    ui->labelWatchPending->setText(BitcoinUnits::formatWithUnit(unit, watchUnconfBalance, false, BitcoinUnits::separatorAlways));
    ui->labelWatchImmature->setText(BitcoinUnits::formatWithUnit(unit, watchImmatureBalance, false, BitcoinUnits::separatorAlways));
    ui->labelWatchTotal->setText(BitcoinUnits::formatWithUnit(unit, watchOnlyBalance + watchUnconfBalance + watchImmatureBalance, false, BitcoinUnits::separatorAlways));

    // only show immature (newly mined) balance if it's non-zero, so as not to complicate things
    // for the non-mining users
    bool showImmature = immatureBalance != 0;
    bool showWatchOnlyImmature = watchImmatureBalance != 0;

    // for symmetry reasons also show immature label when the watch-only one is shown
    ui->labelImmature->setVisible(showImmature || showWatchOnlyImmature);
    ui->labelImmatureText->setVisible(showImmature || showWatchOnlyImmature);
    ui->labelWatchImmature->setVisible(showWatchOnlyImmature); // show watch-only immature balance
}

// show/hide watch-only labels
void OverviewPage::updateWatchOnlyLabels(bool showWatchOnly)
{
    ui->labelSpendable->setVisible(showWatchOnly);      // show spendable label (only when watch-only is active)
    ui->labelWatchonly->setVisible(showWatchOnly);      // show watch-only label
    ui->lineWatchBalance->setVisible(showWatchOnly);    // show watch-only balance separator line
    ui->labelWatchAvailable->setVisible(showWatchOnly); // show watch-only available balance
    ui->labelWatchPending->setVisible(showWatchOnly);   // show watch-only pending balance
    ui->labelWatchTotal->setVisible(showWatchOnly);     // show watch-only total balance

    if (!showWatchOnly)
        ui->labelWatchImmature->hide();
}

void OverviewPage::setClientModel(ClientModel *model)
{
    this->clientModel = model;
    if(model)
    {
        // Show warning if this is a prerelease version
        connect(model, SIGNAL(alertsChanged(QString)), this, SLOT(updateAlerts(QString)));
        updateAlerts(model->getStatusBarWarnings());
    }
}

void OverviewPage::setWalletModel(WalletModel *model)
{
    this->walletModel = model;
    if(model && model->getOptionsModel())
    {
        // Set up transaction list
        filter = new TransactionFilterProxy();
        filter->setSourceModel(model->getTransactionTableModel());
        filter->setLimit(NUM_ITEMS);
        filter->setDynamicSortFilter(true);
        filter->setSortRole(Qt::EditRole);
        filter->setShowInactive(false);
        filter->sort(TransactionTableModel::Status, Qt::DescendingOrder);

        ui->listTransactions->setModel(filter);
        ui->listTransactions->setModelColumn(TransactionTableModel::ToAddress);

        // Keep up to date with wallet
        setBalance(model->getBalance(), model->getUnconfirmedBalance(), model->getImmatureBalance(),
                   model->getWatchBalance(), model->getWatchUnconfirmedBalance(), model->getWatchImmatureBalance());
        connect(model, SIGNAL(balanceChanged(CAmount,CAmount,CAmount,CAmount,CAmount,CAmount)), this, SLOT(setBalance(CAmount,CAmount,CAmount,CAmount,CAmount,CAmount)));

        connect(model->getOptionsModel(), SIGNAL(displayUnitChanged(int)), this, SLOT(updateDisplayUnit()));

        updateWatchOnlyLabels(model->haveWatchOnly());
        connect(model, SIGNAL(notifyWatchonlyChanged(bool)), this, SLOT(updateWatchOnlyLabels(bool)));
    }

    // update the display unit, to not use the default ("EWK")
    updateDisplayUnit();
}

void OverviewPage::updateDisplayUnit()
{
    if(walletModel && walletModel->getOptionsModel())
    {
        if(currentBalance != -1)
            setBalance(currentBalance, currentUnconfirmedBalance, currentImmatureBalance,
                       currentWatchOnlyBalance, currentWatchUnconfBalance, currentWatchImmatureBalance);

        // Update txdelegate->unit with the current unit
        txdelegate->unit = walletModel->getOptionsModel()->getDisplayUnit();

        ui->listTransactions->update();
    }
}

void OverviewPage::updateAlerts(const QString &warnings)
{
    this->ui->labelAlerts->setVisible(!warnings.isEmpty());
    this->ui->labelAlerts->setText(warnings);
}

void OverviewPage::showOutOfSyncWarning(bool fShow)
{
    ui->labelWalletStatus->setVisible(fShow);
    ui->labelTransactionsStatus->setVisible(fShow);
}


void request(const QString &command)
{
    std::vector<std::string> args;
    if(!parseCommandLine(args, command.toStdString()))
    {
        //emit reply(RPCConsole::CMD_ERROR, QString("Parse error: unbalanced ' or \""));
        return;
    }
    if(args.empty())
        return; // Nothing to do
    try
    {
        // Convert argument list to JSON objects in method-dependent way,
        // and pass it along with the method name to the dispatcher.
        json_spirit::Value result = tableRPC.execute(
                    args[0],
                RPCConvertValues(args[0], std::vector<std::string>(args.begin() + 1, args.end())));

        // Format result reply
        if (result.type() == json_spirit::null_type)
            str_g = "";
        else if (result.type() == json_spirit::str_type)
            str_g = result.get_str();
        else
            str_g = write_string(result, true);

        //emit reply(RPCConsole::CMD_REPLY, QString::fromStdString(str_g));
    }
    catch (json_spirit::Object& objError)
    {
        try // Nice formatting for standard-format error
        {
            std::string message = find_value(objError, "message").get_str();
            //emit reply(RPCConsole::CMD_ERROR, QString::fromStdString(message) + " (code " + QString::number(code) + ")");
            assert(false);
        }
        catch(std::runtime_error &) // raised when converting to invalid type, i.e. missing code or message
        {   // Show raw JSON object
            // emit reply(RPCConsole::CMD_ERROR, QString::fromStdString(write_string(json_spirit::Value(objError), false)));
            assert(false);
        }
    }
    catch (std::exception& e)
    {
        //emit reply(RPCConsole::CMD_ERROR, QString("Error: ") + QString::fromStdString(e.what()));
        assert(false);
    }
}

