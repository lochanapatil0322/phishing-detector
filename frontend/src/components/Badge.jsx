const COLORS = {
  Safe: "green",
  Suspicious: "amber",
  Phishing: "red",
};

export default function Badge({ verdict }) {
  const color = COLORS[verdict] || "amber";
  return <span className={`badge badge-${color}`}>{verdict}</span>;
}