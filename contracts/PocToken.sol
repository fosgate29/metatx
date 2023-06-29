// SPDX-License-Identifier: UNLICENSED
pragma solidity 0.8.19;

import "@opengsn/contracts/src/ERC2771Recipient.sol";

import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/token/ERC1155/extensions/ERC1155URIStorage.sol";
import "@openzeppelin/contracts/security/Pausable.sol";
import "@openzeppelin/contracts/utils/Strings.sol";
import "@openzeppelin/contracts/access/Ownable.sol"; // it is necessary for OpenSea accepts it as a collection

contract PocToken is
    ERC2771Recipient,
    ERC1155URIStorage,
    Pausable,
    AccessControl,
    Ownable
{
    /**
     * @dev Emitted when an `amount` of token `id` is minted to `account` by `sender`.
     */
    event Minted(address sender, address account, uint256 id, uint256 amount);

    /**
     * @dev Emitted when an `amount` of token `id` from `account` is burned by `sender`.
     */
    event Burned(address sender, address account, uint256 id, uint256 amount);

    /**
     * @dev Emitted when Admin transfer tokens from an address
     */
    event AdminTransferred(
        address sender,
        address from,
        address to,
        uint256 id,
        uint256 amount
    );

    /**
     * @dev Emitted when an `amount` of token `id` is batch minted to `account` is by `sender`.
     */
    event MintBatched(
        address sender,
        address account,
        uint256[] ids,
        uint256[] amounts
    );

    /**
     * @dev Emitted when an `amount` of token `id` from `account` is batch burned by `sender`.
     */
    event BurnBatched(
        address sender,
        address account,
        uint256[] ids,
        uint256[] amounts
    );

    /// @dev id -> totalSupply
    mapping(uint256 => uint256) private _totalSupply;

    /// @notice Role that can burn tokens
    bytes32 public constant BURNER_ROLE = keccak256("BURNER_ROLE");

    /// @notice Role that can mint tokens
    bytes32 public constant MINTER_ROLE = keccak256("MINTER_ROLE");

    string internal contractUri;

    /**
     * @dev Grants `DEFAULT_ADMIN_ROLE`, `MINTER_ROLE`, and `BURNER_ROLE` to the account that
     * deploys the contract.
     */
    constructor(string memory _uri, address _forwarder) ERC1155(_uri) {
        _setupRole(DEFAULT_ADMIN_ROLE, _msgSender());

        _setupRole(BURNER_ROLE, _msgSender());
        _setupRole(MINTER_ROLE, _msgSender());

        // 0xB2b5841DBeF766d4b521221732F9B618fCf34A87 FWD in Mumbai
        _setTrustedForwarder(_forwarder);
    }

    function contractURI() public view returns (string memory) {
        return contractUri;
    }

    /// @dev Sets contractURI of the license tokens.
    function setContractURI(
        string memory _contractUri
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        require(bytes(_contractUri).length > 0, "Contract URI was not set");
        contractUri = _contractUri;
    }

    /**
     * @dev Total amount of tokens in with a given id.
     */
    function totalSupply(uint256 _id) public view virtual returns (uint256) {
        return _totalSupply[_id];
    }

    /**
     * @dev Indicates whether any token exist with a given id, or not.
     */
    function exists(uint256 _id) external view virtual returns (bool) {
        return totalSupply(_id) > 0;
    }

    /**
     * Mint a token. Only MINTER_ROLE can call this function
     * @param _account Account that will receive token
     * @param _id Token id
     * @param _amount Amount that will be minted
     */
    function mint(
        address _account,
        uint256 _id,
        uint256 _amount
    ) external whenNotPaused {
        require(
            hasRole(MINTER_ROLE, _msgSender()),
            "Must have minter role to mint"
        );
        _mint(_account, _id, _amount, "");

        emit Minted(_msgSender(), _account, _id, _amount);
    }

    /**
     * Mint multiple tokens. Only MINTER_ROLE can call this function
     * @param _account Account that will receive token
     * @param _ids Tokens ids
     * @param _amounts Amounts that will be minted for each token
     */
    function mintBatch(
        address _account,
        uint256[] calldata _ids,
        uint256[] calldata _amounts
    ) external whenNotPaused {
        require(hasRole(MINTER_ROLE, _msgSender()), "Must have minter role");

        // It checks if ids and amounts length mismatch
        _mintBatch(_account, _ids, _amounts, "");

        emit MintBatched(_msgSender(), _account, _ids, _amounts);
    }

    /**
     * Burn a certain amount of the token. Only BURNER_ROLE can call this function
     * @param _account Account that will have a token burned
     * @param _id Tokens id that will be burned
     * @param _amount Amount that will be burned
     */
    function burn(
        address _account,
        uint256 _id,
        uint256 _amount
    ) external whenNotPaused {
        require(
            hasRole(BURNER_ROLE, _msgSender()),
            "Must have burner role to burn"
        );
        _burn(_account, _id, _amount);

        emit Burned(_msgSender(), _account, _id, _amount);
    }

    /**
     * Burn multiple tokens. Only BURNER_ROLE can call this function
     * @param _account Account that will have tokens burned
     * @param _ids Tokens ids that will be burned
     * @param _amounts Amounts that will be burned for each token
     */
    function burnBatch(
        address _account,
        uint256[] memory _ids,
        uint256[] memory _amounts
    ) external whenNotPaused {
        require(hasRole(BURNER_ROLE, _msgSender()), "Must have burner role");

        // It checks if ids and amounts length mismatch
        _burnBatch(_account, _ids, _amounts);

        emit BurnBatched(_msgSender(), _account, _ids, _amounts);
    }

    /**
     * @dev Transfer tokens from an account.
     * @param _to Address that will receive tokens
     * @param _id Token id that will be transferred
     * @param _amount Token amount to be transferred
     */
    function transfer(address _to, uint256 _id, uint256 _amount) external {
        bytes memory data;
        _safeTransferFrom(_msgSender(), _to, _id, _amount, data);

        emit AdminTransferred(_msgSender(), _msgSender(), _to, _id, _amount);
    }

    /**
     * @dev Sets `tokenURI` as the tokenURI of `tokenId`. Must have DEFAULT_ADMIN_ROLE.
     */
    function setTokenURI(uint256 _tokenId, string memory _tokenURI) external {
        require(
            hasRole(DEFAULT_ADMIN_ROLE, _msgSender()),
            "Must have admin role"
        );
        _setURI(_tokenId, _tokenURI);
    }

    /**
     * @dev Sets `baseURI` as the `_baseURI` for all tokens. Must have DEFAULT_ADMIN_ROLE.
     */
    function setBaseTokenURI(string memory _baseURI) external {
        require(
            hasRole(DEFAULT_ADMIN_ROLE, _msgSender()),
            "Must have admin role"
        );
        _setBaseURI(_baseURI);
    }

    /// @dev Pause Mint and Burn functions
    function pause() external whenNotPaused {
        require(
            hasRole(DEFAULT_ADMIN_ROLE, _msgSender()),
            "Must have admin role"
        );
        _pause();
    }

    /// @dev Unpause Mint and Burn functions
    function unpause() external whenPaused {
        require(
            hasRole(DEFAULT_ADMIN_ROLE, _msgSender()),
            "Must have admin role"
        );
        _unpause();
    }

    /**
     * @dev See {ERC1155-_beforeTokenTransfer}.
     */
    function _beforeTokenTransfer(
        address _operator,
        address _from,
        address _to,
        uint256[] memory _ids,
        uint256[] memory _amounts,
        bytes memory _data
    ) internal virtual override {
        super._beforeTokenTransfer(
            _operator,
            _from,
            _to,
            _ids,
            _amounts,
            _data
        );

        // Code to update totalSupply when minting
        if (_from == address(0)) {
            for (uint256 i = 0; i < _ids.length; ++i) {
                _totalSupply[_ids[i]] += _amounts[i];
            }
        }

        // Code to udpate totalSupply when burning
        if (_to == address(0)) {
            for (uint256 i = 0; i < _ids.length; ++i) {
                uint256 id = _ids[i];
                uint256 amount = _amounts[i];
                uint256 supply = _totalSupply[id];
                require(supply >= amount, "ERC1155: exceeds totalSupply");
                unchecked {
                    _totalSupply[id] = supply - amount;
                }
            }
        }
    }

    function supportsInterface(
        bytes4 _interfaceId
    ) public view virtual override(ERC1155, AccessControl) returns (bool) {
        return super.supportsInterface(_interfaceId);
    }

    function _msgSender()
        internal
        view
        override(Context, ERC2771Recipient)
        returns (address sender)
    {
        sender = ERC2771Recipient._msgSender();
    }

    function _msgData()
        internal
        view
        override(Context, ERC2771Recipient)
        returns (bytes calldata)
    {
        return ERC2771Recipient._msgData();
    }
}
