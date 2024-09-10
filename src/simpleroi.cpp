// simpleroi.cpp
#include "simpleroi.h"
#include "chainparams.h"
#include "gamemasterman.h"
#include <inttypes.h>
#include <univalue.h>
#include "validation.h"

const int CSimpRoiArgs::nStakeRoiHrs = 3;	// 3 hour averaging for smooth stake values
const int CSimpRoiArgs::nStakeRoi24Hrs = 24;	// 24 hour averaging for smooth stake values

int64_t CSimpleRoi::getTimeDiff(CSimpRoiArgs& csra, uint64_t n_blocks, int nHeight)
{
    if (nHeight < n_blocks) n_blocks = nHeight;
    csra.pb0 = chainActive[nHeight - n_blocks];
// return timeDiff
    return csra.pb->GetBlockTime() - csra.pb0->GetBlockTime();
}

// returns count enabled or zero on error
int CSimpleRoi::getsroi(CSimpRoiArgs& csra)
{
    csra.pb = chainActive.Tip();
    if (!csra.pb || !csra.pb->nHeight) return 0;

// calculation values
    int nHeight			= csra.pb->nHeight;				// height of tip
    int nTargetSpacing		= Params().GetConsensus().nTargetSpacing;	// MINUTES per block in seconds
    int nTimeSlotLength		= Params().GetConsensus().nTimeSlotLength;	// seconds for time slot
    int64_t nTargetTimespan	= Params().GetConsensus().TargetTimespan(nHeight);	// MINUTES in seconds to measure 'hashes per sec'
    CAmount nGMCollateral	= Params().GetConsensus().nGMCollateralAmt;
    CAmount nGMreward		= GetGamemasterPayment(nHeight);				// masternode reward
    CAmount nBlockValue		= GetBlockValue(nHeight);				// block reward
    CAmount nStakeReward	= nBlockValue - nGMreward;
    int nGMblocks		= 2 * 1440 * 60;				// 2 days for blocks per day average

// Calculate network hashes per second over 3 hours
    uint64_t n_blocks_3hr = csra.nStakeRoiHrs * 3600 / nTargetSpacing;
    int64_t timeDiff_3hr = getTimeDiff(csra, n_blocks_3hr, nHeight);
    if (timeDiff_3hr <= 0) return -2;	// no negative or divide by zero exceptions
    arith_uint256 workDiff_3hr = csra.pb->nChainWork - csra.pb0->nChainWork;
    int64_t nSmoothNetHashPS_3hr = (int64_t)(workDiff_3hr.getdouble() / timeDiff_3hr);

// Calculate network hashes per second over 24 hours
    uint64_t n_blocks_24hr = CSimpRoiArgs::nStakeRoi24Hrs * 3600 / nTargetSpacing;
    int64_t timeDiff_24hr = getTimeDiff(csra, n_blocks_24hr, nHeight);
    if (timeDiff_24hr <= 0) return -2;	// no negative or divide by zero exceptions
    arith_uint256 workDiff_24hr = csra.pb->nChainWork - csra.pb0->nChainWork;
    int64_t nSmoothNetHashPS_24hr = (int64_t)(workDiff_24hr.getdouble() / timeDiff_24hr);

// -----------------------------------------------------------------------
// calculate network hashes per second over TargetTimespan
    uint64_t n_blocks = nTargetTimespan / nTargetSpacing;
    int64_t timeDiff = getTimeDiff(csra, n_blocks, nHeight);
    if (timeDiff <= 0) return -1;	// no negative or divide by zero exceptions
    arith_uint256 workDiff = csra.pb->nChainWork - csra.pb0->nChainWork;
    int64_t networkHashPS = (int64_t)(workDiff.getdouble() / timeDiff);

// --------------------------------------------------------------------
// calculate total staked coins
    csra.stakedCoins = (CAmount)(networkHashPS * nTimeSlotLength / 1000000);
// calculate smoothed staked coins for 3-hour and 24-hour periods
    csra.smoothCoins = (CAmount)(nSmoothNetHashPS_3hr * nTimeSlotLength / 1000000);
    csra.smoothCoins24Hrs = (CAmount)(nSmoothNetHashPS_24hr * nTimeSlotLength / 1000000); // New variable for 24-hour smoothed coins
// ----------------------------------------------------------------------------
// calculate average blocks per day
    n_blocks = nGMblocks / nTargetSpacing;
    timeDiff = getTimeDiff(csra, n_blocks, nHeight);
    if (timeDiff <= 0) return -3;	// no negative or divide by zero exceptions
    csra.nBlocksPerDay = (float)86400 * (n_blocks -1) / timeDiff;
// --------------------------------------------------------------
// calculate staking ROI -- StakedRewardsPerYear / stakedCoins
    csra.nStakingRoi = (float)(nStakeReward * csra.nBlocksPerDay * 365 / (networkHashPS * nTimeSlotLength));
// calculate smooth staking ROI for 3-hour and 24-hour periods
    csra.nSmoothRoi = (float)(nStakeReward * csra.nBlocksPerDay * 365 / (nSmoothNetHashPS_3hr * nTimeSlotLength));
    csra.nSmoothRoi24Hrs = (float)(nStakeReward * csra.nBlocksPerDay * 365 / (nSmoothNetHashPS_24hr * nTimeSlotLength)); // New variable for 24-hour ROI
// -----------------------------------------------------------------------------------------------------------
// calculate total masternode collateral
    int nEnabled = gamemasterman.CountEnabled();
    if (nEnabled <= 0) return 0;
    csra.mnCoins = (CAmount)(nGMCollateral * nEnabled / 100000000);
// ---------------------------------------------------------------
// calculate masternode ROI -- reward * blocks_per_day * 365 / collateral
    csra.nGMRoi = (float)(nGMreward * csra.nBlocksPerDay * 36500 / (nGMCollateral * nEnabled));
// return enabled masternodes
    return nEnabled;
}

// convert COIN to string with thousands comma separators
std::string CSimpleRoi::CAmount2Kwithcommas(CAmount koin) {
    std::string s = strprintf("%" PRId64, (int64_t)koin);
    int j = 0;
    std::string k;

    for (int i = s.size() - 1; i >= 0;) {
        k.push_back(s[i]);
        j++;
        i--;
        if (j % 3 == 0 && i >= 0) k.push_back(',');
    }
    reverse(k.begin(), k.end());
    return k;
};


bool CSimpleRoi::generateROI(UniValue& roi, std::string& sGerror)
{
    CSimpRoiArgs csra;
    int nEnabled = getsroi(csra);
    if (nEnabled <= 0) {
        sGerror = strprintf("Not enough valid data %d", nEnabled);
         return false;
    }
    roi.pushKV(strprintf("%d hour avg ROI", csra.nStakeRoiHrs), strprintf("%4.1f%%", csra.nSmoothRoi));
    roi.pushKV(strprintf("%d hour avg ROI", csra.nStakeRoi24Hrs), strprintf("%4.1f%%", csra.nSmoothRoi24Hrs)); // Add 24-hour ROI to output
    roi.pushKV(strprintf("%2d min stk ROI", Params().GetConsensus().TargetTimespan(csra.pb->nHeight) / 60), strprintf("%4.1f%%", csra.nStakingRoi));
    roi.pushKV("network  stake", CAmount2Kwithcommas(csra.smoothCoins));
    roi.pushKV("24hr network stake", CAmount2Kwithcommas(csra.smoothCoins24Hrs)); // Add 24-hour network stake to output
    roi.pushKV("--------------","--------------");
    roi.pushKV("Gamemaster ROI", strprintf("%4.1f%%", csra.nGMRoi));
    roi.pushKV("tot collateral", CAmount2Kwithcommas(csra.mnCoins));
    roi.pushKV("enabled  nodes", strprintf("%d", nEnabled));
    roi.pushKV("blocks per day", strprintf("%4.1f", csra.nBlocksPerDay));
    return true;
}
