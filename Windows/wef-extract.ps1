# Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope Process
# Ruta base de las suscripciones en el Registro
$subscriptionsPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\EventCollector\Subscriptions"

# Verificar si la ruta existe
if (Test-Path $subscriptionsPath) {
    $subscriptions = Get-ChildItem -Path $subscriptionsPath

    # Recorrer cada suscripción
    foreach ($subscription in $subscriptions) {
        # Ruta completa de la suscripción
        $subscriptionPath = Join-Path -Path $subscriptionsPath -ChildPath $subscription.PSChildName

        # Obtener el valor del campo "Query"
        $query = Get-ItemProperty -Path $subscriptionPath -Name Query -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Query

        # Mostrar resultados
        if ($query) {
            Write-Host "Subscripción: $($subscription.PSChildName)" -ForegroundColor Yellow
            Write-Host "Query:"
            Write-Host $query -ForegroundColor Green
            Write-Host "--------------------------------------------" -ForegroundColor Cyan
        } else {
            Write-Host "Subscripción: $($subscription.PSChildName)" -ForegroundColor Yellow
            Write-Host "No se encontró un campo 'Query'." -ForegroundColor Red
            Write-Host "--------------------------------------------" -ForegroundColor Cyan
        }
    }
} else {
    Write-Host "No se encontró la ruta de suscripciones en el Registro." -ForegroundColor Red
}