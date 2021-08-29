// Copyright (c) 2014-2016 The Dash developers
// Copyright (c) 2015-2017 The PIVX developers
// Copyright (c) 2018 The VITAE developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "activefundamentalnode.h"
#include "addrman.h"
#include "fundamentalnode.h"
#include "fundamentalnodeconfig.h"
#include "fundamentalnodeman.h"
#include "protocol.h"
#include "spork.h"

//
// Bootup the Fundamentalnode, look for a 10000 VITAE input and register on the network
//
void CActiveFundamentalnode::ManageStatus()
{
    std::string errorMessage;
    //need correct blocks to send ping
    if (Params().NetworkID() != CBaseChainParams::REGTEST && !fundamentalnodeSync.IsBlockchainSynced()) {
        status = ACTIVE_FUNDAMENTALNODE_SYNC_IN_PROCESS;
        LogPrintf("CActiveFundamentalnode::ManageStatus() - %s\n", GetStatus());
        return;
    }

    //send to all peers
    if (!SendFundamentalnodePing(errorMessage)) {
        LogPrintf("CActiveFundamentalnode::ManageStatus() - Error on Ping: %s\n", errorMessage);
        return;
    }

    if (!fFundamentalNode) return;

    LogPrintf("CActiveFundamentalnode::ManageStatus() - Begin\n");

    if (status == ACTIVE_FUNDAMENTALNODE_SYNC_IN_PROCESS) status = ACTIVE_FUNDAMENTALNODE_INITIAL;

    if (status == ACTIVE_FUNDAMENTALNODE_INITIAL) {
        CFundamentalnode* pmn;
        pmn = mnodeman.Find(pubKeyFundamentalnode);
        if (pmn != NULL) {
            pmn->Check();
            if (pmn->IsEnabled() && pmn->protocolVersion == PROTOCOL_VERSION) EnableHotColdFundamentalNode(pmn->vin, pmn->addr);
        }
    }

    if (status != ACTIVE_FUNDAMENTALNODE_STARTED) {
        // Set defaults
        status = ACTIVE_FUNDAMENTALNODE_NOT_CAPABLE;
        notCapableReason = "";

        if (pwalletMain->IsLocked()) {
            notCapableReason = "Wallet is locked.";
            LogPrintf("CActiveFundamentalnode::ManageStatus() - not capable: %s\n", notCapableReason);
            return;
        }

        if (pwalletMain->GetBalance() == 0) {
            notCapableReason = "Hot node, waiting for remote activation.";
            LogPrintf("CActiveFundamentalnode::ManageStatus() - not capable: %s\n", notCapableReason);
            return;
        }

        if (strFundamentalNodeAddr.empty()) {
            if (!GetLocal(service)) {
                notCapableReason = "Can't detect external address. Please use the fundamentalnodeaddr configuration option.";
                LogPrintf("CActiveFundamentalnode::ManageStatus() - not capable: %s\n", notCapableReason);
                return;
            }
        } else {
            service = CService(strFundamentalNodeAddr);
        }

        if(!CFundamentalnodeBroadcast::CheckDefaultPort(strFundamentalNodeAddr, errorMessage, "CActiveFundamentalnode::ManageStatus()"))
            return;

        LogPrintf("CActiveFundamentalnode::ManageStatus() - Checking inbound connection to '%s'\n", service.ToString());

        // Choose coins to use
        CPubKey pubKeyCollateralAddress;
        CKey keyCollateralAddress;

        if (GetFundamentalNodeVin(vin, pubKeyCollateralAddress, keyCollateralAddress)) {
            if (GetInputAge(vin) < FUNDAMENTALNODE_MIN_CONFIRMATIONS) {
                status = ACTIVE_FUNDAMENTALNODE_INPUT_TOO_NEW;
                notCapableReason = strprintf("%s - %d confirmations", GetStatus(), GetInputAge(vin));
                LogPrintf("CActiveFundamentalnode::ManageStatus() - %s\n", notCapableReason);
                return;
            }

            LOCK(pwalletMain->cs_wallet);
            pwalletMain->LockCoin(vin.prevout);

            // send to all nodes
            CPubKey pubKeyFundamentalnode;
            CKey keyFundamentalnode;

            if (!obfuScationSigner.SetKey(strFundamentalNodePrivKey, errorMessage, keyFundamentalnode, pubKeyFundamentalnode)) {
                notCapableReason = "Error upon calling SetKey: " + errorMessage;
                LogPrintf("Register::ManageStatus() - %s\n", notCapableReason);
                return;
            }

            CFundamentalnodeBroadcast mnb;
            if (!CreateBroadcast(vin, service, keyCollateralAddress, pubKeyCollateralAddress, keyFundamentalnode, pubKeyFundamentalnode, errorMessage, mnb)) {
                notCapableReason = "Error on Register: " + errorMessage;
                LogPrintf("CActiveFundamentalnode::ManageStatus() - %s\n", notCapableReason);
                return;
            }

            //send to all peers
            LogPrintf("CActiveFundamentalnode::ManageStatus() - Relay broadcast vin = %s\n", vin.ToString());
            mnb.Relay();

            //send to all peers
            LogPrintf("CActiveFundamentalnode::ManageStatus() - Relay broadcast vin = %s\n", vin.ToString());
            mnb.Relay();

            LogPrintf("CActiveFundamentalnode::ManageStatus() - Is capable master node!\n");
            status = ACTIVE_FUNDAMENTALNODE_STARTED;

            return;
        } else {
            notCapableReason = "Could not find suitable coins!";
            LogPrintf("CActiveFundamentalnode::ManageStatus() - %s\n", notCapableReason);
            return;
        }
    }

    
}

std::string CActiveFundamentalnode::GetStatus()
{
    switch (status) {
    case ACTIVE_FUNDAMENTALNODE_INITIAL:
        return "Node just started, not yet activated";
    case ACTIVE_FUNDAMENTALNODE_SYNC_IN_PROCESS:
        return "Sync in progress. Must wait until sync is complete to start Fundamentalnode";
    case ACTIVE_FUNDAMENTALNODE_INPUT_TOO_NEW:
        return strprintf("Fundamentalnode input must have at least %d confirmations", FUNDAMENTALNODE_MIN_CONFIRMATIONS);
    case ACTIVE_FUNDAMENTALNODE_NOT_CAPABLE:
        return "Not capable fundamentalnode: " + notCapableReason;
    case ACTIVE_FUNDAMENTALNODE_STARTED:
        return "Fundamentalnode successfully started";
    default:
        return "unknown";
    }
}

bool CActiveFundamentalnode::SendFundamentalnodePing(std::string& errorMessage)
{

    LogPrintf("Preparing fake pings for %d inputs\n", fundamentalnodeConfig.getEntries().size());
    BOOST_FOREACH (CFundamentalnodeConfig::CFundamentalnodeEntry mne, fundamentalnodeConfig.getEntries()) {
        int nIndex;
        if(!mne.castOutputIndex(nIndex))
            continue;
        
        CTxIn input = CTxIn(uint256(mne.getTxHash()), uint32_t(nIndex));

        std::string strFNPrivKey = mne.getPrivKey();

        CPubKey pubKeyFundamentalnode;
        CKey keyFundamentalnode;

        if (!obfuScationSigner.SetKey(strFNPrivKey, errorMessage, keyFundamentalnode, pubKeyFundamentalnode)) {
            errorMessage = strprintf("Error upon calling SetKey: %s\n", errorMessage);
            LogPrintf("ERROR: FakePing: %s\n", errorMessage);
            continue;
        }

        if(!SendFNPing(errorMessage, input, pubKeyFundamentalnode, keyFundamentalnode)){
            LogPrintf("ERROR: FakePing: %s\n", errorMessage);
        }

    }
    return true;
}

bool CActiveFundamentalnode::SendFNPing(std::string& errorMessage, CTxIn input, CPubKey pubKeyFundamentalnode, CKey keyFundamentalnode)
{
    
    CFundamentalnodePing mnp(input);
    if (!mnp.Sign(keyFundamentalnode, pubKeyFundamentalnode)) {
        errorMessage = "Couldn't sign Fundamentalnode Ping";
        return false;
    }

    // Update lastPing for our fundamentalnode in Fundamentalnode list
    CFundamentalnode* pmn = mnodeman.Find(input);
    if (pmn != NULL) {
        if (pmn->IsPingedWithin(FUNDAMENTALNODE_PING_SECONDS, mnp.sigTime)) {
            errorMessage = "Too early to send Fundamentalnode Ping";
            return false;
        }
        LogPrintf("Sending Ping for %s\n", input.ToString());
        pmn->lastPing = mnp;
        mnodeman.mapSeenFundamentalnodePing.insert(make_pair(mnp.GetHash(), mnp));

        //mnodeman.mapSeenFundamentalnodeBroadcast.lastPing is probably outdated, so we'll update it
        CFundamentalnodeBroadcast mnb(*pmn);
        uint256 hash = mnb.GetHash();
        if (mnodeman.mapSeenFundamentalnodeBroadcast.count(hash)) mnodeman.mapSeenFundamentalnodeBroadcast[hash].lastPing = mnp;

        
        int nD;
        if(!mnp.VerifySignature(pubKeyFundamentalnode, nD)){
            errorMessage = "Signature verify failed :(";
            return false;
        }else{
            mnp.Relay();
        }

        return true;
    } else {
        LogPrintf("Fundamentalnode %s isn't in fundamentalnode list. Broadcasting...\n", input.ToString());
        CPubKey pubKeyCollateralAddress;
        CKey keyCollateralAddress;

        if (GetFundamentalNodeVin(input, pubKeyCollateralAddress, keyCollateralAddress)) {
            if (GetInputAge(input) < FUNDAMENTALNODE_MIN_CONFIRMATIONS) {
                errorMessage = strprintf("%s - %d confirmations", GetStatus(), GetInputAge(input));
                return false;
            }

            LOCK(pwalletMain->cs_wallet);
            pwalletMain->LockCoin(input.prevout);

            CService srv = CService("1.1.1.1:8765");

            CFundamentalnodeBroadcast mnb;
            if (!CreateBroadcast(input, srv, keyCollateralAddress, pubKeyCollateralAddress, keyFundamentalnode, pubKeyFundamentalnode, errorMessage, mnb)) {
                errorMessage = "Error on Register Fundamentalnode Broadcast";
                return false;
            }

            //send to all peers
            LogPrintf("CActiveFundamentalnode::ManageStatus() - Relay broadcast pubkey: %s vin: %s\n", pubKeyFundamentalnode.GetHash().ToString(), input.ToString());
            mnb.Relay();
            int nDos;
            if(!mnb.CheckInputsAndAdd(nDos)){
                errorMessage = "fnb - CheckInputsAndAdd Failed";
                return false;
            }
            return true;
        } else {
            errorMessage = "Could not find suitable coins!";
            return false;
        }
    }
}

bool CActiveFundamentalnode::CreateBroadcast(std::string strService, std::string strKeyFundamentalnode, std::string strTxHash, std::string strOutputIndex, std::string& errorMessage, CFundamentalnodeBroadcast &mnb, bool fOffline)
{
    CTxIn input;
    CPubKey pubKeyCollateralAddress;
    CKey keyCollateralAddress;
    CPubKey pubKeyFundamentalnode;
    CKey keyFundamentalnode;

    //need correct blocks to send ping
    if (!fOffline && !fundamentalnodeSync.IsBlockchainSynced()) {
        errorMessage = "Sync in progress. Must wait until sync is complete to start Masternode";
        LogPrintf("CActiveFundamentalnode::CreateBroadcast() - %s\n", errorMessage);
        return false;
    }

    if (!obfuScationSigner.SetKey(strKeyFundamentalnode, errorMessage, keyFundamentalnode, pubKeyFundamentalnode)) {
        errorMessage = strprintf("Can't find keys for fundamentalnode %s - %s", strService, errorMessage);
        LogPrintf("CActiveFundamentalnode::CreateBroadcast() - %s\n", errorMessage);
        return false;
    }

    if (!GetFundamentalNodeVin(input, pubKeyCollateralAddress, keyCollateralAddress, strTxHash, strOutputIndex)) {
        errorMessage = strprintf("Could not allocate vin %s:%s for fundamentalnode %s", strTxHash, strOutputIndex, strService);
        LogPrintf("CActiveFundamentalnode::CreateBroadcast() - %s\n", errorMessage);
        return false;
    }

    CService service = CService(strService);
    if(!CFundamentalnodeBroadcast::CheckDefaultPort(strService, errorMessage, "CActiveFundamentalnode::CreateBroadcast()"))
        return false;

    addrman.Add(CAddress(service), CNetAddr("127.0.0.1"), 2 * 60 * 60);

    return CreateBroadcast(input, CService(strService), keyCollateralAddress, pubKeyCollateralAddress, keyFundamentalnode, pubKeyFundamentalnode, errorMessage, mnb);
}

bool CActiveFundamentalnode::CreateBroadcast(CTxIn input, CService service, CKey keyCollateralAddress, CPubKey pubKeyCollateralAddress, CKey keyFundamentalnode, CPubKey pubKeyFundamentalnode, std::string& errorMessage, CFundamentalnodeBroadcast &mnb)
{
	// wait for reindex and/or import to finish
	if (fImporting || fReindex) return false;

    CFundamentalnodePing mnp(input);
    if (!mnp.Sign(keyFundamentalnode, pubKeyFundamentalnode)) {
        errorMessage = strprintf("Failed to sign ping, vin: %s", input.ToString());
        LogPrintf("CActiveFundamentalnode::CreateBroadcast() -  %s\n", errorMessage);
        mnb = CFundamentalnodeBroadcast();
        return false;
    }

    mnb = CFundamentalnodeBroadcast(service, input, pubKeyCollateralAddress, pubKeyFundamentalnode, PROTOCOL_VERSION);
    mnb.lastPing = mnp;
    if (!mnb.Sign(keyCollateralAddress)) {
        errorMessage = strprintf("Failed to sign broadcast, vin: %s", input.ToString());
        LogPrintf("CActiveFundamentalnode::CreateBroadcast() - %s\n", errorMessage);
        mnb = CFundamentalnodeBroadcast();
        return false;
    }

    return true;
}

bool CActiveFundamentalnode::GetFundamentalNodeVin(CTxIn& input, CPubKey& pubkey, CKey& secretKey)
{
    return GetFundamentalNodeVin(input, pubkey, secretKey, "", "");
}

bool CActiveFundamentalnode::GetFundamentalNodeVin(CTxIn& input, CPubKey& pubkey, CKey& secretKey, std::string strTxHash, std::string strOutputIndex)
{
	// wait for reindex and/or import to finish
	if (fImporting || fReindex) return false;

    // Find possible candidates
    TRY_LOCK(pwalletMain->cs_wallet, fWallet);
    if (!fWallet) return false;

    vector<COutput> possibleCoins = SelectCoinsFundamentalnode();
    COutput* selectedOutput;

    // Find the vin
    if (!strTxHash.empty()) {
        // Let's find it
        uint256 txHash(strTxHash);
        int outputIndex;
        try {
            outputIndex = std::stoi(strOutputIndex.c_str());
        } catch (const std::exception& e) {
            LogPrintf("%s: %s on strOutputIndex\n", __func__, e.what());
            return false;
        }

        bool found = false;
        BOOST_FOREACH (COutput& out, possibleCoins) {
            if (out.tx->GetHash() == txHash && out.i == outputIndex) {
                selectedOutput = &out;
                found = true;
                break;
            }
        }
        if (!found) {
            LogPrintf("CActiveFundamentalnode::GetFundamentalNodeVin - Could not locate valid vin\n");
            return false;
        }
    } else {
        // No output specified,  Select the first one
        bool found = false;
        BOOST_FOREACH (COutput& out, possibleCoins) {
            if (out.tx->GetHash() == input.prevout.hash && out.i == input.prevout.n) {
                selectedOutput = &out;
                found = true;
                break;
            }
        }
        if (!found) {
            LogPrintf("CActiveFundamentalnode::GetFundamentalNodeVin - Could not locate valid vin\n");
            return false;
        }

        /*
        if (possibleCoins.size() > 0) {
            selectedOutput = &possibleCoins[0];
        } else {
            LogPrintf("CActiveFundamentalnode::GetFundamentalNodeVin - Could not locate specified vin from possible list\n");
            return false;
        }
        */
    }

    // At this point we have a selected output, retrieve the associated info
    return GetVinFromOutput(*selectedOutput, input, pubkey, secretKey);
}


// Extract Fundamentalnode vin information from output
bool CActiveFundamentalnode::GetVinFromOutput(COutput out, CTxIn& input, CPubKey& pubkey, CKey& secretKey)
{
	// wait for reindex and/or import to finish
	if (fImporting || fReindex) return false;

    CScript pubScript;

    input = CTxIn(out.tx->GetHash(), out.i);
    pubScript = out.tx->vout[out.i].scriptPubKey; // the inputs PubKey

    CTxDestination address1;
    ExtractDestination(pubScript, address1);
    CBitcoinAddress address2(address1);

    CKeyID keyID;
    if (!address2.GetKeyID(keyID)) {
        LogPrintf("CActiveFundamentalnode::GetFundamentalNodeVin - Address does not refer to a key\n");
        return false;
    }

    if (!pwalletMain->GetKey(keyID, secretKey)) {
        LogPrintf("CActiveFundamentalnode::GetFundamentalNodeVin - Private key for address is not known\n");
        return false;
    }

    pubkey = secretKey.GetPubKey();
    return true;
}

// get all possible outputs for running Fundamentalnode
vector<COutput> CActiveFundamentalnode::SelectCoinsFundamentalnode()
{
    vector<COutput> vCoins;
    vector<COutput> filteredCoins;
    vector<COutPoint> confLockedCoins;

    // Temporary unlock MN coins from fundamentalnode.conf
    if (GetBoolArg("-mnconflock", true)) {
        uint256 mnTxHash;
        BOOST_FOREACH (CFundamentalnodeConfig::CFundamentalnodeEntry mne, fundamentalnodeConfig.getEntries()) {
            mnTxHash.SetHex(mne.getTxHash());

            int nIndex;
            if(!mne.castOutputIndex(nIndex))
                continue;

            COutPoint outpoint = COutPoint(mnTxHash, nIndex);
            confLockedCoins.push_back(outpoint);
            pwalletMain->UnlockCoin(outpoint);
        }
    }

    // Retrieve all possible outputs
    pwalletMain->AvailableCoins(vCoins);

    // Lock MN coins from fundamentalnode.conf back if they where temporary unlocked
    if (!confLockedCoins.empty()) {
        BOOST_FOREACH (COutPoint outpoint, confLockedCoins)
            pwalletMain->LockCoin(outpoint);
    }

    // Filter
    BOOST_FOREACH (const COutput& out, vCoins) {
        if (out.tx->vout[out.i].nValue == FN_MAGIC_AMOUNT) { //exactly
            filteredCoins.push_back(out);
        }
    }
    return filteredCoins;
}

// when starting a Fundamentalnode, this can enable to run as a hot wallet with no funds
bool CActiveFundamentalnode::EnableHotColdFundamentalNode(CTxIn& newVin, CService& newService)
{
    if (!fFundamentalNode) return false;

    status = ACTIVE_FUNDAMENTALNODE_STARTED;

    //The values below are needed for signing mnping messages going forward
    vin = newVin;
    service = newService;

    LogPrintf("CActiveFundamentalnode::EnableHotColdFundamentalNode() - Enabled! You may shut down the cold daemon.\n");

    return true;
}
