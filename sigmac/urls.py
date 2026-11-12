from django.contrib import admin
from django.urls import path
from clinica import views

urlpatterns = [
    path('admin/', admin.site.urls),
    path('', views.inicio, name='inicio'),
    path('login/', views.login_view, name='login'),
    path('logout/', views.logout_view, name='logout'),
    path('desbloquear/', views.desbloquear_intentos, name='desbloquear_intentos'),
    path('registro/', views.registro_view, name='registro'),
    path('cargar-demo/', views.cargar_datos_demo, name='cargar_datos_demo'),

    # Paneles exclusivos según rol (RBAC)
    path('paciente/', views.panel_paciente, name='panel_paciente'),
    path('comprobante/<int:cita_id>/', views.comprobante_cita, name='comprobante_cita'),
    path('medico/', views.panel_medico, name='panel_medico'),
    path('recepcion/', views.panel_recepcionista, name='panel_recepcionista'),
    path('administracion/', views.panel_admin, name='panel_admin'),
]