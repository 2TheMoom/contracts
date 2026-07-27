// SPDX-License-Identifier: LGPL-3.0-only
pragma solidity ^0.8.17;

import { TestBaseLocal } from "../../utils/TestBaseLocal.sol";
import { InvalidCallData } from "src/Errors/GenericErrors.sol";
import { EmergencyPauseFacet } from "lifi/Facets/EmergencyPauseFacet.sol";
import { DiamondCutFacet } from "lifi/Facets/DiamondCutFacet.sol";
import { DiamondLoupeFacet } from "lifi/Facets/DiamondLoupeFacet.sol";

/// @title EmergencyPauseFacet_UnpauseDoS_PoC
/// @notice Proves that EmergencyPauseFacet::unpauseDiamond() enters an
///         unbounded loop (out-of-gas revert) when the blacklist contains
///         the DiamondCutFacet's address -- the exact same bug class LI.FI
///         already fixed once in DexManagerFacet::batchAddDex() (Cantina
///         competition finding 3.1.2, fixed in commit 47e4d8d7).
///
/// Root cause (src/Facets/EmergencyPauseFacet.sol, unpauseDiamond):
///
///     for (uint256 i; i < _blacklist.length; ) {
///         currentSelectors = LibDiamondLoupe.facetFunctionSelectors(_blacklist[i]);
///         if (currentSelectors[0] == DiamondCutFacet.diamondCut.selector)
///             continue;                  // <-- skips `++i` below
///         ...
///         unchecked { ++i; }
///     }
///
/// `removeFacet()` in the same file enforces the identical invariant
/// correctly via `revert InvalidCallData()`. `unpauseDiamond()` uses
/// `continue` instead, which skips the increment and loops forever on the
/// same index until the transaction runs out of gas.
///
/// Impact: EmergencyPauseFacet is LI.FI's incident-recovery mechanism. If
/// the diamond owner ever needs to unpause while excluding a facet whose
/// first registered selector happens to equal DiamondCutFacet.diamondCut's
/// selector (including a malicious facet an attacker deliberately crafted
/// with a colliding first selector, anticipating exclusion), the recovery
/// call always reverts out-of-gas -- it can never succeed with that facet in
/// the blacklist, regardless of gas provided.
contract EmergencyPauseFacet_UnpauseDoS_PoC is TestBaseLocal {
    EmergencyPauseFacet internal emergencyPauseFacet;

    function setUp() public {
        initTestBaseLocal();
        emergencyPauseFacet = EmergencyPauseFacet(payable(address(diamond)));
        vm.label(address(emergencyPauseFacet), "EmergencyPauseFacet");
    }

    /// @notice Baseline: removeFacet() correctly rejects blacklisting the
    ///         DiamondCutFacet with a cheap, clean revert. This proves the
    ///         *intended* behavior for this exact invariant, and that it is
    ///         achievable -- unpauseDiamond() just doesn't do it.
    function test_RemoveFacet_CorrectlyRevertsCheaply_OnDiamondCutFacet()
        public
    {
        address diamondCutAddress = DiamondLoupeFacet(address(diamond))
            .facetAddress(DiamondCutFacet(address(diamond)).diamondCut.selector);

        vm.startPrank(USER_PAUSER);

        uint256 gasBefore = gasleft();
        vm.expectRevert(InvalidCallData.selector);
        emergencyPauseFacet.removeFacet(diamondCutAddress);
        uint256 gasUsed = gasBefore - gasleft();

        vm.stopPrank();

        // A clean revert should cost a small, bounded amount of gas --
        // nowhere near a full block's worth.
        assertLt(
            gasUsed,
            100_000,
            "removeFacet() should revert cheaply, confirming the correct pattern is achievable"
        );
    }

    /// @notice PoC: unpauseDiamond() with the DiamondCutFacet's address in
    ///         the blacklist consumes (near-)all forwarded gas without
    ///         completing -- the signature of an unbounded loop, not a clean
    ///         revert. The call fails even when given a full mainnet-block
    ///         worth of gas.
    function test_PoC_UnpauseDiamond_InfiniteLoop_OnDiamondCutFacetBlacklist()
        public
    {
        // Resolve the DiamondCutFacet address BEFORE pausing (loupe calls
        // revert while paused), matching the pattern used in LI.FI's own
        // test_CanUnpauseDiamondWithMultiBlacklist().
        address diamondCutAddress = DiamondLoupeFacet(address(diamond))
            .facetAddress(DiamondCutFacet(address(diamond)).diamondCut.selector);

        // Pause the diamond first, exactly as every unpause test in the
        // existing suite does.
        vm.prank(USER_PAUSER);
        emergencyPauseFacet.pauseDiamond();

        address[] memory blacklist = new address[](1);
        blacklist[0] = diamondCutAddress;

        bytes memory callData = abi.encodeWithSelector(
            EmergencyPauseFacet.unpauseDiamond.selector,
            blacklist
        );

        // Forward a full mainnet-block worth of gas via a low-level call.
        // A correctly-implemented guard (like removeFacet's) would revert
        // near-instantly and cheaply, as proven above. An infinite loop
        // instead consumes essentially all of it and still fails.
        uint256 gasStipend = 30_000_000;

        vm.startPrank(USER_DIAMOND_OWNER);
        uint256 gasBefore = gasleft();
        (bool success, ) = address(emergencyPauseFacet).call{
            gas: gasStipend
        }(callData);
        uint256 gasUsed = gasBefore - gasleft();
        vm.stopPrank();

        // The call must fail...
        assertFalse(
            success,
            "unpauseDiamond() should fail when blacklist contains DiamondCutFacet"
        );

        // ...and it must fail by exhausting the overwhelming majority of
        // forwarded gas (unbounded loop / MemoryOOG), NOT by a cheap, clean
        // revert like removeFacet's (which uses <30k gas -- see above).
        // This distinguishes "infinite loop / OOG" from "intended guard".
        assertGt(
            gasUsed,
            (gasStipend * 90) / 100,
            "Call should consume the overwhelming majority of forwarded gas, proving an unbounded loop rather than a clean revert"
        );
    }

    /// @notice Proves this is not merely "expensive" but genuinely
    ///         non-terminating: since `i` never increments once the branch
    ///         is hit, the loop condition `i < _blacklist.length` never
    ///         becomes false. Supplying far more gas than any realistic
    ///         block limit still fails -- there is no gas amount at which
    ///         this call succeeds.
    function test_PoC_NoAmountOfGasCompletesTheCall() public {
        address diamondCutAddress = DiamondLoupeFacet(address(diamond))
            .facetAddress(DiamondCutFacet(address(diamond)).diamondCut.selector);

        vm.prank(USER_PAUSER);
        emergencyPauseFacet.pauseDiamond();

        address[] memory blacklist = new address[](1);
        blacklist[0] = diamondCutAddress;

        bytes memory callData = abi.encodeWithSelector(
            EmergencyPauseFacet.unpauseDiamond.selector,
            blacklist
        );

        // ~3.3x a real mainnet block gas limit (30M). If this were merely
        // "expensive", a large enough stipend would eventually let it
        // complete. It does not.
        uint256 hugeGasStipend = 100_000_000;

        vm.startPrank(USER_DIAMOND_OWNER);
        (bool success, ) = address(emergencyPauseFacet).call{
            gas: hugeGasStipend
        }(callData);
        vm.stopPrank();

        assertFalse(
            success,
            "Call still fails even with 100M gas (3.3x a real block limit) -- confirms non-termination, not just high cost"
        );
    }

    /// @notice Confirms the diamond remains permanently paused after the
    ///         failed unpause attempt -- the recovery mechanism is fully
    ///         blocked, not just that one call.
    function test_PoC_DiamondRemainsStuckPaused_AfterFailedUnpauseAttempt()
        public
    {
        address diamondCutAddress = DiamondLoupeFacet(address(diamond))
            .facetAddress(DiamondCutFacet(address(diamond)).diamondCut.selector);

        vm.prank(USER_PAUSER);
        emergencyPauseFacet.pauseDiamond();

        address[] memory blacklist = new address[](1);
        blacklist[0] = diamondCutAddress;

        bytes memory callData = abi.encodeWithSelector(
            EmergencyPauseFacet.unpauseDiamond.selector,
            blacklist
        );

        vm.startPrank(USER_DIAMOND_OWNER);
        (bool success, ) = address(emergencyPauseFacet).call{
            gas: 30_000_000
        }(callData);
        vm.stopPrank();

        assertFalse(success, "unpause attempt should have failed");

        // Diamond should still be paused -- DiamondLoupe calls should still
        // revert with DiamondIsPaused, proving the owner has no way to
        // recover via this code path while this facet is in the blacklist.
        vm.expectRevert();
        DiamondLoupeFacet(address(diamond)).facets();
    }
}
