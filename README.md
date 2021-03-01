# VoFSQ

VoFSQ: An Efficient File-Sharing Consensus Protocol

Verifications of File-Sharing Qualification (VoFSQ). VoFSQ allows file-holders to verify with each other whether the shared-file has been preserved for a period of time. It also ensures that the content of shared-file is indeed what the file downloader wants under the condition that more than 2/3 participants are honest. Compared to the consensus protocol of Filecoin, VoFSQ is more efficient in the prover and verifier proof phases, because it uses a simple shared-file associated Proof of SpaceTime (PoST) to complete the qualification verification. Meanwhile, VoFSQ does not disclose the private information of shared-file during the consensus process, and does not rely on trusted third parties
