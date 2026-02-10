import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { useTheme } from "@/components/theme-provider"
import { useSettingsStore } from "@/store/useSettingsStore"
import { Moon, Sun, Laptop } from "lucide-react"
import { RadioGroup, RadioGroupItem } from "@/components/ui/radio-group"

export default function Settings() {
  const { setTheme, theme } = useTheme()
  const { backendUrl, setBackendUrl } = useSettingsStore()

  return (
    <div className="space-y-6">
      <h1 className="text-3xl font-bold tracking-tight">Настройки</h1>
      
      <div className="grid gap-6">
        <Card>
          <CardHeader>
            <CardTitle>Подключение к серверу</CardTitle>
          </CardHeader>
          <CardContent className="space-y-4">
            <RadioGroup value={backendUrl} onValueChange={setBackendUrl}>
              <div className="flex items-center space-x-2">
                <RadioGroupItem value="http://168.222.194.141:8000" id="remote" />
                <Label htmlFor="remote">Сервер (168.222.194.141)</Label>
              </div>
              <div className="flex items-center space-x-2">
                <RadioGroupItem value="http://127.0.0.1:8000" id="local" />
                <Label htmlFor="local">Локальный (127.0.0.1:8000)</Label>
              </div>
            </RadioGroup>
            <div className="pt-2">
               <Label htmlFor="custom-url" className="text-xs text-muted-foreground">Текущий адрес API:</Label>
               <Input id="custom-url" value={backendUrl} onChange={(e) => setBackendUrl(e.target.value)} className="mt-1" />
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle>Внешний вид</CardTitle>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="space-y-2">
              <Label>Тема оформления</Label>
              <div className="flex gap-2">
                <Button 
                  variant={theme === "light" ? "default" : "outline"}
                  onClick={() => setTheme("light")}
                  className="gap-2"
                >
                  <Sun className="h-4 w-4" /> Светлая
                </Button>
                <Button 
                  variant={theme === "dark" ? "default" : "outline"}
                  onClick={() => setTheme("dark")}
                  className="gap-2"
                >
                  <Moon className="h-4 w-4" /> Темная
                </Button>
                <Button 
                  variant={theme === "system" ? "default" : "outline"}
                  onClick={() => setTheme("system")}
                  className="gap-2"
                >
                  <Laptop className="h-4 w-4" /> Системная
                </Button>
              </div>
            </div>
          </CardContent>
        </Card>
      </div>
    </div>
  )
}
