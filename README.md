# did:webvh interoperability demo (DCS 2026)

- `issuer/did.jsonl` — 데모 발급자 did:webvh 로그 (did:web 호환 문서: `issuer/did.json`)
- `holder/did.jsonl` — 보유자 did:webvh 로그 (브라우저 지갑에서 생성, 개인키는 브라우저에만 존재)
- `index.html` — 브라우저 지갑 + 검증자 페이지 (eddsa-jcs-2022, did:webvh 1.0 로그 검증)

데모 발급자는 실제 기관이 아니며, VC의 이름 값은 자기 신고(self-asserted)입니다.

- `chain.html` — Sepolia + MetaMask: OnchainIdRegistry·TokenSecurity(da-contracts, 무수정 컴파일)·DidWebvhAnchor 배포,
  did:webvh VP 검증 통과 시에만 addIdentity/addClaim 등록, 토큰 게이트·롤백 탐지·클레임 회수 시연
- `contracts.json` — 위 3개 컨트랙트의 ABI·바이트코드 (solc 0.8.28, OpenZeppelin 5.1.0)
- `contracts/DidWebvhAnchor.sol` — 지갑↔DID 바인딩 + DID 로그 versionId 앵커링
- `roles.html` — 역할 분리 시연: 운영자(Account 1)·투자자 A/B(Account 2/3), 투자자 간 전송, KYC 회수, forcedTransfer
