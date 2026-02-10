import { useState } from "react"
import { useNavigate } from "react-router-dom"
import { useAuthStore } from "@/store/useAuthStore"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Loader2 } from "lucide-react"

export default function Otp() {
  const navigate = useNavigate()
  const verifyOtp = useAuthStore((state) => state.verifyOtp)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState(false)
  const [code, setCode] = useState("")

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    setLoading(true)
    setError(false)
    try {
      const isValid = await verifyOtp(code)
      if (isValid) {
        navigate("/")
      } else {
        setError(true)
      }
    } catch (error) {
      console.error(error)
      setError(true)
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="flex min-h-screen items-center justify-center bg-muted/40 p-4">
      <Card className="w-full max-w-sm text-center">
        <CardHeader>
          <CardTitle className="text-2xl">Подтверждение входа</CardTitle>
          <CardDescription>
            Мы отправили код подтверждения на вашу почту. Введите его ниже.
            (Для демо: 1234)
          </CardDescription>
        </CardHeader>
        <CardContent>
          <form onSubmit={handleSubmit} className="space-y-4">
            <div className="flex justify-center">
              <Input 
                className="w-32 text-center text-2xl tracking-widest" 
                maxLength={4} 
                value={code}
                onChange={(e) => setCode(e.target.value)}
                placeholder="0000"
              />
            </div>
            {error && <p className="text-sm text-destructive">Неверный код</p>}
            <Button type="submit" className="w-full" disabled={loading || code.length < 4}>
              {loading && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}
              Подтвердить
            </Button>
          </form>
        </CardContent>
      </Card>
    </div>
  )
}
