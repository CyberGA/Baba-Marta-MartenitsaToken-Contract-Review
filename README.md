# Baba Marta MartenitsaToken Contract Audit Report

Prepared by: [CyberGA](https://github.com/CyberGA) and [prcabrah](https://github.com/prcabrah) via [AlgorinthLabs](https://github.com/Algorinth-Labs)
## Table of contents
- [Disclaimer](#disclaimer)
- [Protocol Summary](#protocol-summary)
- [Audit Scope](#scope)
- [Roles](#roles)
- [Issues Found](#issues-found)
- [Findings](#findings)
- [Tools Used](#tools-used)


<h2 id="disclaimer">Disclaimer</h2>

<p>This audit was conducted by CyberGA and prcabrah, a team affiliated with AlgorinthLabs LLC, as part of a voluntary competition entry. The team dedicated significant time and resources to identify potential security vulnerabilities within the codebase during the competition timeframe. It is important to note that while this report details our findings, neither CyberGA nor prcabrah nor AlgorinthLabs LLC assumes any responsibility for the outcome. Furthermore, this audit should not be interpreted as an implicit endorsement of the associated business or product. The assessment had a predefined time constraint and was solely focused on evaluating the security posture of the Solidity implementation within the smart contracts.</p>

<h2 id="protocol-summary">Protocol Summary</h2>

The "Baba Marta" protocol allows you to buy `MartenitsaToken` and to give it away to friends. Also, if you want, you can be a producer. The producer creates `MartenitsaTokens` and sells them. There is also a voting for the best `MartenitsaToke`n. Only producers can participate with their own `MartenitsaTokens`. The other users can only vote. The winner wins 1 `HealthToken`. If you are not a producer and you want a `HealthToken`, you can receive one if you have 3 different `MartenitsaTokens`. More `MartenitsaTokens` more `HealthTokens`. The `HealthToken` is a ticket to a special event (producers are not able to participate). During this event each participant has producer role and can create and sell own `MartenitsaTokens`.

<h2 id="scope">Audit Scope</h2>

```
├── src
│   ├── HealthToken.sol
│   ├── MartenitsaEvent.sol
│   ├── MartenitsaMarketplace.sol
│   ├── MartenitsaToken.sol
|   ├── MartenitsaVoting.sol
│   ├── SpecialMartenitsaToken.sol
```

## Roles

Producer - Should be able to create martenitsa and sell it. The producer can also buy martenitsa, make present and participate in vote. The martenitsa of producer can be candidate for the winner of voting.

User - Should be able to buy martenitsa and make a present to someone else. The user can collect martenitsa tokens and for every 3 different martenitsa tokens will receive 1 health token. The user is also able to participate in a special event and to vote for one of the producer's martenitsa.

## Issues Found

| Severity          | Number of issues found |
| ----------------- | ---------------------- |
| High              | 3                      |
| Medium            | 0                      |
| Low               | 3                      |
| Info              | 0                      |
| Gas Optimizations | 1                      |
| Total             | 7                      |


## Findings

## 1.  `MartenitsaToken::updateCountMartenitsaTokensOwner`

### [H-1] Integer overflow/underflow
The code doesn't directly check for overflow or underflow. It simply increments or decrements the count without any boundary checks.
If `countMartenitsaTokensOwner[owner]` is already 0 (meaning the address owns zero tokens), then subtracting 1 would result in an underflow. 
In Solidity, underflow with unsigned integers (like uint) wraps around to the maximum value instead of throwing an error.
If `countMartenitsaTokensOwner[owner]` is already at its maximum value for an unsigned integer (uint256), adding 1 to it will cause an integer overflow. Solidity doesn't automatically revert when an overflow occurs, so without additional checks, the overflow will result in unexpected behavior and potential security vulnerabilities

*Instance*:
```solidity
file: src/MartenitsaToken.sol

function updateCountMartenitsaTokensOwner(address owner, string memory operation) external {
  ...
  countMartenitsaTokensOwner[owner] += 1;
  ...
  countMartenitsaTokensOwner[owner] -= 1;
  ...
}
```

### Recommendation:

Use `SafeMath` library functions to perform arithmetic operations safely, ensuring that no overflow or underflow occurs.

Sample:

```Solidity
//using SafeMath for uint256;

function updateCountMartenitsaTokensOwner(address owner, string action) public  {
  ...
  countMartenitsaTokensOwner[owner] = countMartenitsaTokensOwner[owner].add(1);
  ...
  countMartenitsaTokensOwner[owner] = countMartenitsaTokensOwner[owner].sub(1);
  ...
}
```

## 2.  `MartenitsaEvent::joinEvent`
### [L-1] Does not check if event has started
It lacks a check to ensure that the event has started before allowing participants to join. Without this check, participants could join before the event begins, which might not be intended behavior

*Instance*:
```solidity
file: src/MartenitsaEvent.sol

function joinEvent() external {
  ...
}
```

### Recommendation:
When the `joinEvent` function is called, it should check if the event has started

Sample:

```Solidity
function joinEvent() external {
   require(block.timestamp > eventStartTime, "Event has not started yet");
  ...
}
```

### [H-2] Reentrancy
The joinEvent function allows external calls before completing internal state changes, which could potentially lead to reentrancy attacks.
There's a potential indirect reentrancy vulnerability depending on how the _healthToken contract behaves.

*Instance*:
```solidity
file: src/MartenitsaEvent.sol

function joinEvent() external {
  ...
}
```

### Recommendation:
Ensure that all internal state changes are made before external calls

Sample:

```Solidity
function joinEvent() external {
  ...
  _addProducer(msg.sender);
  (bool success) = _healthToken.transferFrom(msg.sender, address(this), healthTokenRequirement);
  require(success, "The transfer is not successful");
}
```
## 3.  `MartenitsaMarketplace::buyMartenitsa`
### [H-3] Reentrancy
After transferring funds to the seller using `seller.call{value: salePrice}("")`, the function immediately transfers the token to the buyer using `martenitsaToken.safeTransferFrom(seller, buyer, tokenId)`. If the token transfer triggers a call to an external contract that can execute arbitrary code (a malicious fallback function), it could potentially re-enter the buyMartenitsa function before it completes, allowing the seller to re-enter and manipulate the state again

*Instance*:
```solidity
file: src/MartenitsaMarketplace.sol

function buyMartenitsa(uint256 tokenId) external payable {
  ...
}
```

### Recommendation:
Ensure that all internal state changes are made before external calls.
Transfer token to buyer first before updating their count states

Sample:

```Solidity
function buyMartenitsa(uint256 tokenId) external payable {
    Listing storage listing = tokenIdToListing[tokenId];
    require(listing.forSale, "Token is not listed for sale");
    require(msg.value >= listing.price, "Insufficient funds");

    address seller = listing.seller;
    address buyer = msg.sender;
    uint256 salePrice = listing.price;

    // Clear the listing
    delete tokenIdToListing[tokenId];

    martenitsaToken.safeTransferFrom(seller, buyer, tokenId);

    // Update token counts after the transfer
    martenitsaToken.updateCountMartenitsaTokensOwner(buyer, "add");
    martenitsaToken.updateCountMartenitsaTokensOwner(seller, "sub");

    // Transfer funds to seller after all state changes
    (bool sent, ) = seller.call{value: salePrice}("");
    require(sent, "Failed to send Ether");

    // Emit event after all actions are completed
    emit MartenitsaSold(tokenId, buyer, salePrice);
}
```

## 4.  `MartenitsaVoting.sol`
### [L-2] Voting mechanism
An address can only vote for only one token because the `hasVoted` is set to true after the address has voted for the first token.
This means that an address will not be able to carry out votes on other token.

*Instance*:
```solidity
file: src/MartenitsaVoting.sol

  ...
  //mapping user address -> if this address is already voted
  mapping(address => bool) public hasVoted;
  ...

  function voteForMartenitsa(uint256 tokenId) external {
        require(!hasVoted[msg.sender], "You have already voted");
        ...

        hasVoted[msg.sender] = true;
        ...
    }
  ...
```

### Recommendation:
Improve code logic implementation

Sample:

```Solidity
 ...
  // Mapping: MartenitsaTokenId -> Mapping: VoterAddress -> HasVoted
  mapping(uint256 => mapping(address => bool)) private hasVoted;
  ...

  function voteForMartenitsa(uint256 tokenId) external {
        require(!hasVoted[msg.sender], "You have already voted");
        ...

        _hasVoted[tokenId][msg.sender] = true;
        ...
    }
  ...
```

### [G-1] The _tokenIds array is initialized but never cleared after use
The _tokenIds array is initialized but never cleared after use. 
This could potentially lead to increased gas costs and unintended behavior if the array grows too large over time. 

*Instance*:
```solidity
file: src/MartenitsaVoting.sol

  ...
  function announceWinner() external onlyOwner {
        ...
    }
  ...
```

### Recommendation:
Consider clearing the array after the winner is announced or using a more efficient data structure if the array needs to persist.

Sample:

```Solidity
 ...
  function announceWinner() external onlyOwner {
        require(block.timestamp >= startVoteTime + duration, "The voting is active");

        uint256 winnerTokenId;
        uint256 maxVotes = 0;

        for (uint256 i = 0; i < _tokenIds.length; i++) {
            if (voteCounts[_tokenIds[i]] > maxVotes) {
                maxVotes = voteCounts[_tokenIds[i]];
                winnerTokenId = _tokenIds[i];
            }
        }

        list = _martenitsaMarketplace.getListing(winnerTokenId);
        _healthToken.distributeHealthToken(list.seller, 1);

        emit WinnerAnnounced(winnerTokenId, list.seller);

        // Clear the _tokenIds array
        delete _tokenIds;
    }
  ...
```

### [L-3] Does not check if voting is active
The `voteForMartenitsa`function only check if the voting has not expired.
It does not check if the voting has started

*Instance*:
```solidity
file: src/MartenitsaVoting.sol

  ...
  function announceWinner() external onlyOwner {
        ...
    }
  ...
```

### Recommendation:
Consider adding modifier to check if voting is active

Sample:

```Solidity
 ...
  function voteForMartenitsa(uint256 tokenId) external {
        ...
        require(block.timestamp >= startVoteTime && block.timestamp < startVoteTime + duration, "Voting period is not active");
        ...
    }
  ...
```

## Tools Used
- Remix IDE was used to test for the above risks or issues
- Also, manual inspection was done

