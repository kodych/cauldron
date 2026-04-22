import type { ReactNode } from 'react';

// Shared badge styling for every compact status marker in the UI —
// NEW / GONE / EXPLOIT / VULN / KEV / OWNED / TARGET / confidence tags,
// etc. Individual sites used to ship their own ad-hoc Tailwind combos
// with drifted opacity (/30 vs /40) and font-weight (semibold vs bold
// vs unset), producing visual noise on rows that carry multiple
// markers. This component is the one source of truth.

type Tone =
  | 'red'     // EXPLOIT, TARGET, critical
  | 'orange'  // KEV (via strong variant), high severity
  | 'yellow'  // CHANGED, mid severity
  | 'green'   // NEW, OWNED, PIVOT
  | 'blue'    // mitigated, info
  | 'purple'  // VULN (no exploit)
  | 'gray';   // GONE, neutral

interface Props {
  tone: Tone;
  children: ReactNode;
  // `strong` bumps opacity and uses a lighter text tone — reserved for
  // signals that should dominate among other badges on the same row
  // (currently only KEV uses it, to telegraph "actively exploited").
  strong?: boolean;
  title?: string;
}

const TONE_CLASSES: Record<Tone, { normal: string; strong: string }> = {
  red:    { normal: 'bg-red-900/30 text-red-400',       strong: 'bg-red-900/40 text-red-300' },
  orange: { normal: 'bg-orange-900/30 text-orange-400', strong: 'bg-orange-900/40 text-orange-300' },
  yellow: { normal: 'bg-yellow-900/30 text-yellow-400', strong: 'bg-yellow-900/40 text-yellow-300' },
  green:  { normal: 'bg-green-900/30 text-green-400',   strong: 'bg-green-900/40 text-green-300' },
  blue:   { normal: 'bg-blue-900/30 text-blue-400',     strong: 'bg-blue-900/40 text-blue-300' },
  purple: { normal: 'bg-purple-900/30 text-purple-400', strong: 'bg-purple-900/40 text-purple-300' },
  gray:   { normal: 'bg-gray-700 text-gray-400',        strong: 'bg-gray-700 text-gray-300' },
};

export function Badge({ tone, children, strong = false, title }: Props) {
  const tones = TONE_CLASSES[tone];
  const weight = strong ? 'font-bold' : 'font-semibold';
  return (
    <span
      className={`inline-flex items-center gap-0.5 rounded px-1.5 py-0.5 text-xs ${weight} ${strong ? tones.strong : tones.normal}`}
      title={title}
    >
      {children}
    </span>
  );
}
