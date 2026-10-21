// Brand mark: a turnout — one track in (sleepers on the left), two out. The
// yellow branch is the lane out via the overseas pool, the white one is
// handed back to the firewall. The "道岔" in the name. Flat colours with a
// solid offset shadow. Keep in sync with web/public/favicon.svg.
export default function Logo({ size = 32 }: { size?: number }) {
  return (
    <svg width={size} height={size} viewBox="0 0 64 64" aria-hidden="true" className="logo">
      <rect width="64" height="64" rx="16" fill="#2f6bff" />
      <g stroke="#86abff" strokeWidth="4" strokeLinecap="round">
        <path d="M12 24 V 40" />
        <path d="M20 24 V 40" />
      </g>
      <g fill="none" strokeLinecap="round" strokeWidth="10" stroke="#1c4ad6" transform="translate(0 3)">
        <path d="M22 32 C 34 32, 37 17, 51 17" />
        <path d="M9 32 H 22 C 34 32, 37 47, 51 47" />
      </g>
      <g fill="none" strokeLinecap="round" strokeWidth="10">
        <path d="M22 32 C 34 32, 37 17, 51 17" stroke="#ffc53d" />
        <path d="M9 32 H 22 C 34 32, 37 47, 51 47" stroke="#ffffff" />
      </g>
    </svg>
  );
}
