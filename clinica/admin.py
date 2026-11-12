from django.contrib import admin
from .models import (
    Especialidad, BoxAtencion, Paciente, Medico,
    Recepcionista, Administrador, HorarioMedico, CitaMedica, HistorialClinico
)

admin.site.register(Especialidad)
admin.site.register(BoxAtencion)
admin.site.register(Paciente)
admin.site.register(Medico)
admin.site.register(Recepcionista)
admin.site.register(Administrador)
admin.site.register(HorarioMedico)
admin.site.register(CitaMedica)
admin.site.register(HistorialClinico)