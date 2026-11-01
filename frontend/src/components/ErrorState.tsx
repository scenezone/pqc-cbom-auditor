export default function ErrorState({ message }: { message: string }) {
  return <div className="card border-red-500/40"><p className="text-red-400">{message}</p></div>
}
