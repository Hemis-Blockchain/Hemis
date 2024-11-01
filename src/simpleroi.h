// simpleroi.h
#ifndef CSIMPLE_ROI_H
#define CSIMPLE_ROI_H

#include "amount.h"
#include "chain.h"
#include <string>
#include <univalue.h>

class CSimpRoiArgs
{
public:					// things passed between functions
    float	nGMRoi;
    float	nStakingRoi;
    float	nSmoothRoi;
    float   nSmoothRoi24Hrs;
    float	nBlocksPerDay;
    CBlockIndex *pb;
    CBlockIndex	*pb0;
    CAmount	mnCoins;
    CAmount	stakedCoins;
    CAmount	smoothCoins;
    CAmount	smoothCoins24Hrs;
    static const int nStakeRoiHrs;	// initialized in simpleroi.cpp
    static const int nStakeRoi24Hrs;
};

class CSimpleRoi
{
public:
    bool generateROI(UniValue& roi, std::string& sGerror);

private:
// returns timeDiff over nBlocks
    int64_t getTimeDiff(CSimpRoiArgs& csra, uint64_t nblocks, int nHeight);
// convert COIN to string with thousands comma seperators
    std::string CAmount2Kwithcommas(CAmount koin);
//  returns enabled masternode, populates CsimpRoiArgs
    int getsroi(CSimpRoiArgs& csra);
};

#endif	// CSIMPLE_ROI_H