import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"

export default function Resources() {
  return (
    <div className="space-y-6">
      <h1 className="text-3xl font-bold tracking-tight">Ресурсы</h1>
      <Card>
        <CardHeader>
          <CardTitle>Список ресурсов</CardTitle>
        </CardHeader>
        <CardContent>
          <p className="text-muted-foreground">Здесь будет список сотрудников и оборудования.</p>
        </CardContent>
      </Card>
    </div>
  )
}
