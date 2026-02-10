import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import { Button } from "@/components/ui/button"
import { Plus } from "lucide-react"

const projects = [
  { id: 1, name: "Разработка сайта", manager: "Иванов И.И.", start: "01.01.2025", end: "01.03.2025", status: "В работе", progress: 45 },
  { id: 2, name: "Внедрение CRM", manager: "Петров П.П.", start: "10.01.2025", end: "20.04.2025", status: "Планирование", progress: 0 },
  { id: 3, name: "Миграция БД", manager: "Сидоров С.С.", start: "05.02.2025", end: "15.02.2025", status: "Завершено", progress: 100 },
]

export default function Projects() {
  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h1 className="text-3xl font-bold tracking-tight">Банк проектов</h1>
        <Button>
          <Plus className="mr-2 h-4 w-4" /> Новый проект
        </Button>
      </div>

      <Card>
        <CardHeader>
          <CardTitle>Все проекты</CardTitle>
        </CardHeader>
        <CardContent>
          <div className="rounded-md border">
            <table className="w-full text-sm">
              <thead className="border-b bg-muted/50">
                <tr className="text-left">
                  <th className="p-4 font-medium text-muted-foreground">Название</th>
                  <th className="p-4 font-medium text-muted-foreground">Руководитель</th>
                  <th className="p-4 font-medium text-muted-foreground">Начало</th>
                  <th className="p-4 font-medium text-muted-foreground">Окончание</th>
                  <th className="p-4 font-medium text-muted-foreground">Статус</th>
                  <th className="p-4 font-medium text-muted-foreground">Прогресс</th>
                </tr>
              </thead>
              <tbody>
                {projects.map((p) => (
                  <tr key={p.id} className="border-b last:border-0 hover:bg-muted/10 transition-colors">
                    <td className="p-4 font-medium">{p.name}</td>
                    <td className="p-4">{p.manager}</td>
                    <td className="p-4">{p.start}</td>
                    <td className="p-4">{p.end}</td>
                    <td className="p-4">
                      <span className={`inline-flex items-center rounded-full px-2.5 py-0.5 text-xs font-semibold ${
                        p.status === "Завершено" ? "bg-green-100 text-green-800" :
                        p.status === "В работе" ? "bg-blue-100 text-blue-800" :
                        "bg-yellow-100 text-yellow-800"
                      }`}>
                        {p.status}
                      </span>
                    </td>
                    <td className="p-4">
                      <div className="flex items-center gap-2">
                        <div className="h-2 w-full max-w-[100px] rounded-full bg-secondary">
                          <div 
                            className="h-full rounded-full bg-primary" 
                            style={{ width: `${p.progress}%` }} 
                          />
                        </div>
                        <span className="text-xs text-muted-foreground">{p.progress}%</span>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </CardContent>
      </Card>
    </div>
  )
}
