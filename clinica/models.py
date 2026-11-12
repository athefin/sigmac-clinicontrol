"""
Módulo de Modelos de Datos - Sistema SIGMAC (CliniControl).
Implementa las 10 entidades de la Vista Lógica (Usuario/User, Paciente, Medico,
Recepcionista, Administrador, Especialidad, BoxAtencion, HorarioMedico,
CitaMedica e HistorialClinico).
"""
from django.db import models
from django.contrib.auth.models import User


class Especialidad(models.Model):
    """Representa una especialidad médica dentro del centro de salud."""
    nombre = models.CharField(max_length=100, unique=True)
    descripcion = models.CharField(max_length=250, blank=True)

    def __str__(self):
        return self.nombre


class BoxAtencion(models.Model):
    """Representa el espacio físico (box clínico) donde se realiza la consulta."""
    numero_box = models.IntegerField(unique=True)
    piso = models.IntegerField(default=1)
    estado_box = models.BooleanField(default=True, help_text="True = Operativo / Libre")

    def __str__(self):
        return f"Box {self.numero_box} (Piso {self.piso})"


class Paciente(models.Model):
    """Perfil de Paciente que hereda credenciales de la superclase User."""
    usuario = models.OneToOneField(User, on_delete=models.CASCADE)
    rut = models.CharField(max_length=12, unique=True)
    fecha_nacimiento = models.DateField(null=True, blank=True)
    telefono = models.CharField(max_length=15)
    prevision = models.CharField(max_length=50, choices=[
        ('FONASA', 'Fonasa'),
        ('ISAPRE', 'Isapre'),
        ('PARTICULAR', 'Particular')
    ], default='FONASA')

    def __str__(self):
        return f"{self.usuario.first_name} {self.usuario.last_name} ({self.rut})"


class Medico(models.Model):
    """Perfil de Médico vinculado a una Especialidad y a la superclase User."""
    usuario = models.OneToOneField(User, on_delete=models.CASCADE)
    rut = models.CharField(max_length=12, unique=True)
    especialidad = models.ForeignKey(Especialidad, on_delete=models.PROTECT)
    numero_registro_salud = models.CharField(max_length=50)

    def __str__(self):
        return f"Dr(a). {self.usuario.first_name} {self.usuario.last_name} - {self.especialidad.nombre}"


class Recepcionista(models.Model):
    """Perfil de Recepcionista encargado de la gestión presencial y telefónica."""
    usuario = models.OneToOneField(User, on_delete=models.CASCADE)
    rut = models.CharField(max_length=12, unique=True)
    turno = models.CharField(max_length=50, default="Diurno (08:00 - 17:00)")

    def __str__(self):
        return f"Recepcionista: {self.usuario.first_name} {self.usuario.last_name}"


class Administrador(models.Model):
    """Perfil de Administrador Técnico encargado de configurar boxes y horarios."""
    usuario = models.OneToOneField(User, on_delete=models.CASCADE)
    rut = models.CharField(max_length=12, unique=True)
    nivel_acceso = models.IntegerField(default=1)

    def __str__(self):
        return f"Admin: {self.usuario.first_name} {self.usuario.last_name}"


class HorarioMedico(models.Model):
    """Bloques de tiempo configurados para cada médico."""
    medico = models.ForeignKey(Medico, on_delete=models.CASCADE)
    fecha = models.DateField()
    hora_inicio = models.TimeField()
    hora_fin = models.TimeField()
    estado_disponibilidad = models.BooleanField(default=True, help_text="True = Disponible")

    def __str__(self):
        estado = "Disponible" if self.estado_disponibilidad else "Ocupado"
        return f"{self.medico} | {self.fecha} ({self.hora_inicio.strftime('%H:%M')}) - {estado}"


class CitaMedica(models.Model):
    """Entidad transaccional que une Paciente, Médico, Box y Horario."""
    ESTADOS = [
        ('Confirmada', 'Confirmada'),
        ('Atendida', 'Atendida'),
        ('Anulada', 'Anulada'),
    ]
    paciente = models.ForeignKey(Paciente, on_delete=models.CASCADE)
    medico = models.ForeignKey(Medico, on_delete=models.CASCADE)
    box = models.ForeignKey(BoxAtencion, on_delete=models.PROTECT)
    horario = models.OneToOneField(HorarioMedico, on_delete=models.CASCADE)
    estado = models.CharField(max_length=20, choices=ESTADOS, default='Confirmada')
    fecha_creacion = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"Cita #{self.id} - {self.paciente} con {self.medico}"


class HistorialClinico(models.Model):
    """Ficha clínica confidencial (Ley 20.584) asociada por composición al Paciente."""
    paciente = models.ForeignKey(Paciente, on_delete=models.CASCADE, related_name='historiales')
    medico = models.ForeignKey(Medico, on_delete=models.PROTECT)
    cita = models.OneToOneField(CitaMedica, on_delete=models.SET_NULL, null=True, blank=True)
    fecha_registro = models.DateTimeField(auto_now_add=True)
    diagnostico = models.TextField()
    receta = models.TextField(blank=True)
    observaciones = models.TextField(blank=True)

    def __str__(self):
        return f"Ficha #{self.id} - {self.paciente} ({self.fecha_registro.strftime('%d/%m/%Y')})"