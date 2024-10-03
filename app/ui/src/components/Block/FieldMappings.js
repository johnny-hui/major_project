import {blockStyles} from "./styles";

export const getFieldMappings = () => {
    return ([
        { key: 'hash', label: 'Hash', style: blockStyles.blockInfoHash },
        { key: 'previous_hash', label: 'Previous Hash', style: blockStyles.blockInfoText },
        { key: 'ip_addr', label: "Peer's IP Address", style: blockStyles.blockInfoText },
        { key: 'signers_ip', label: "Signer's IP Address", style: blockStyles.blockInfoText },
        { key: 'signers_role', label: "Signer's Role", style: blockStyles.blockInfoText },
        { key: 'pub_key', label: "Signer’s Public Key", style: blockStyles.blockInfoText },
        { key: 'timestamp', label: 'Timestamp', style: blockStyles.blockInfoText },
        { key: 'signature', label: 'Signature', style: blockStyles.blockInfoSignature }
  ]);
}
