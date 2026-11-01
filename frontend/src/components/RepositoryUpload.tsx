import { useRef } from 'react'
import { CheckCircle2, FileArchive, Upload, X } from 'lucide-react'

interface Props {
  selectedFile?: File | null
  onFileSelected: (f: File | null) => void
}

export default function RepositoryUpload({ selectedFile, onFileSelected }: Props) {
  const ref = useRef<HTMLInputElement>(null)

  const formatSize = (bytes: number) => {
    if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`
    return `${(bytes / (1024 * 1024)).toFixed(2)} MB`
  }

  return (
    <div>
      <h2 className="text-sm font-medium text-slate-200">Repository archive</h2>
      <p className="mt-1 text-xs leading-5 text-slate-500">
        Choose a ZIP file. Static analysis checks supported source files; repository code is never executed.
      </p>

      <input
        ref={ref}
        type="file"
        accept=".zip"
        className="hidden"
        onChange={e => {
          const f = e.target.files?.[0]
          if (f) onFileSelected(f)
        }}
      />

      {selectedFile ? (
        <div className="mt-4 flex items-center justify-between gap-3 rounded-xl border border-cyan-300/20 bg-cyan-300/[0.04] p-4">
          <div className="flex items-center gap-3">
            <div className="flex h-10 w-10 shrink-0 items-center justify-center rounded-lg bg-cyan-200/10 text-cyan-100">
              <FileArchive className="h-6 w-6" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <span className="max-w-[220px] truncate text-sm font-medium text-slate-100">{selectedFile.name}</span>
                <CheckCircle2 className="h-4 w-4 text-emerald-400" />
              </div>
              <span className="text-xs text-slate-500">{formatSize(selectedFile.size)}</span>
            </div>
          </div>
          <div className="flex items-center gap-2">
            <button
              type="button"
              className="rounded-lg px-2.5 py-1.5 text-xs text-slate-300 hover:bg-white/[0.07]"
              onClick={() => ref.current?.click()}
            >
              Change
            </button>
            <button
              type="button"
              className="rounded-lg p-1.5 text-slate-500 hover:bg-rose-300/10 hover:text-rose-200"
              onClick={() => {
                if (ref.current) ref.current.value = ''
                onFileSelected(null)
              }}
              title="Remove file"
            >
              <X className="h-4 w-4" />
            </button>
          </div>
        </div>
      ) : (
        <button
          type="button"
          className="btn-secondary mt-4 w-full justify-center border-dashed !py-5"
          onClick={() => ref.current?.click()}
        >
          <Upload className="h-4 w-4 text-cyan-200" /> Select ZIP archive
        </button>
      )}
    </div>
  )
}
