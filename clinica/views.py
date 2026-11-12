"""
Controladores y Vistas del Sistema SIGMAC (CliniControl).
Aplica controles de seguridad OWASP Top 10:
- A01: Broken Access Control (Validación estricta de rol en cada vista).
- A03: Injection (Consultas parametrizadas mediante Django ORM).
- A07: Identification and Authentication Failures (Hashing PBKDF2 y sesiones seguras).
"""
from datetime import date, time, timedelta
from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.decorators import login_required
from django.contrib.auth.models import User
from django.contrib import messages
from django.db import transaction
from .models import (
    Especialidad, BoxAtencion, Paciente, Medico,
    Recepcionista, Administrador, HorarioMedico, CitaMedica, HistorialClinico
)


def obtener_rol_usuario(user):
    """Determina el rol exacto del usuario autenticado para aplicar RBAC."""
    if not user.is_authenticated:
        return None
    if hasattr(user, 'paciente'):
        return 'PACIENTE'
    if hasattr(user, 'medico'):
        return 'MEDICO'
    if hasattr(user, 'recepcionista'):
        return 'RECEPCIONISTA'
    if hasattr(user, 'administrador') or user.is_superuser:
        return 'ADMIN'
    return None


def redirigir_segun_rol(user):
    """Redirige automáticamente a cada actor a su panel exclusivo (UC-01)."""
    rol = obtener_rol_usuario(user)
    if rol == 'PACIENTE':
        return redirect('panel_paciente')
    elif rol == 'MEDICO':
        return redirect('panel_medico')
    elif rol == 'RECEPCIONISTA':
        return redirect('panel_recepcionista')
    elif rol == 'ADMIN':
        return redirect('panel_admin')
    return redirect('inicio')


def inicio(request):
    """Página de bienvenida y sección informativa 'Sobre Nuestra Clínica'."""
    especialidades = Especialidad.objects.all()
    medicos = Medico.objects.all()
    return render(request, 'clinica/inicio.html', {
        'especialidades': especialidades,
        'medicos': medicos,
        'rol_actual': obtener_rol_usuario(request.user)
    })


def login_view(request):
    """
    UC-01: Autenticación de Usuario por RUN y contraseña.
    Incluye control de intentos fallidos en sesión (OWASP A07).
    """
    if request.user.is_authenticated:
        return redirigir_segun_rol(request.user)

    intentos = request.session.get('intentos_fallidos', 0)

    if request.method == 'POST':
        if intentos >= 5:
            messages.error(
                request,
                "Por su seguridad, la cuenta fue bloqueada temporalmente tras varios intentos. "
                "Presione 'Desbloquear / Reiniciar intentos' abajo o intente más tarde."
            )
            return redirect('login')

        rut_ingresado = request.POST.get('rut', '').strip()
        password = request.POST.get('password', '')

        usuario_autenticado = authenticate(request, username=rut_ingresado, password=password)

        if usuario_autenticado is not None:
            request.session['intentos_fallidos'] = 0
            login(request, usuario_autenticado)
            messages.success(
                request,
                f"¡Qué alegría verle, {usuario_autenticado.first_name}! Bienvenido(a) a su portal."
            )
            return redirigir_segun_rol(usuario_autenticado)
        else:
            request.session['intentos_fallidos'] = intentos + 1
            restantes = max(0, 5 - (intentos + 1))
            messages.error(
                request,
                f"El RUT o la contraseña no coinciden. Por favor revise los números "
                f"(Intentos restantes: {restantes})."
            )

    return render(request, 'clinica/login.html', {'intentos': intentos})


def desbloquear_intentos(request):
    """Permite limpiar el contador de intentos en el entorno de demostración MVP."""
    request.session['intentos_fallidos'] = 0
    messages.info(request, "Contador de seguridad reiniciado. Ya puede intentar ingresar nuevamente.")
    return redirect('login')


def logout_view(request):
    """Cierra la sesión activa de forma segura."""
    logout(request)
    messages.info(request, "Ha salido de su cuenta de forma segura. ¡Hasta pronto!")
    return redirect('inicio')


def registro_view(request):
    """
    RF-01: Registro guiado de nuevos Pacientes con validación de RUT duplicado.
    """
    if request.user.is_authenticated:
        return redirigir_segun_rol(request.user)

    if request.method == 'POST':
        rut = request.POST.get('rut', '').strip()
        nombres = request.POST.get('nombres', '').strip()
        apellidos = request.POST.get('apellidos', '').strip()
        fecha_nacimiento = request.POST.get('fecha_nacimiento')
        telefono = request.POST.get('telefono', '').strip()
        correo = request.POST.get('correo', '').strip()
        prevision = request.POST.get('prevision', 'FONASA')
        password = request.POST.get('password', '')

        if not rut or not nombres or not apellidos or not password:
            messages.error(request, "Por favor complete todos los campos marcados como obligatorios.")
            return render(request, 'clinica/registro.html')

        if User.objects.filter(username=rut).exists() or Paciente.objects.filter(rut=rut).exists():
            messages.error(
                request,
                "El RUT ingresado ya tiene una cuenta registrada en nuestra clínica."
            )
            return render(request, 'clinica/registro.html')

        with transaction.atomic():
            nuevo_user = User.objects.create_user(
                username=rut,
                email=correo,
                password=password,
                first_name=nombres,
                last_name=apellidos
            )
            Paciente.objects.create(
                usuario=nuevo_user,
                rut=rut,
                fecha_nacimiento=fecha_nacimiento if fecha_nacimiento else None,
                telefono=telefono,
                prevision=prevision
            )

        messages.success(
            request,
            "¡Su cuenta fue creada con éxito! Ahora escriba su RUT y su clave para entrar."
        )
        return redirect('login')

    return render(request, 'clinica/registro.html')


# ==============================================================================
# VISTAS EXCLUSIVAS POR ROL (RBAC - OWASP A01)
# ==============================================================================

@login_required(login_url='login')
def panel_paciente(request):
    """Panel exclusivo para el rol PACIENTE (UC-02 y UC-04)."""
    if obtener_rol_usuario(request.user) != 'PACIENTE':
        messages.warning(request, "Acceso restringido: Esta pantalla es exclusiva para Pacientes.")
        return redirigir_segun_rol(request.user)

    paciente = request.user.paciente
    especialidad_id = request.GET.get('especialidad', '').strip()

    horarios_disponibles = HorarioMedico.objects.filter(
        estado_disponibilidad=True
    ).select_related('medico', 'medico__especialidad').order_by('fecha', 'hora_inicio')

    if especialidad_id and especialidad_id.isdigit():
        horarios_disponibles = horarios_disponibles.filter(medico__especialidad_id=int(especialidad_id))

    if request.method == 'POST':
        accion = request.POST.get('accion')

        if accion == 'reservar':
            horario_id = request.POST.get('horario_id')
            with transaction.atomic():
                horario = get_object_or_404(HorarioMedico, id=horario_id)
                if not horario.estado_disponibilidad:
                    messages.error(
                        request,
                        "Lo sentimos, esa hora médica acaba de ser tomada por otro paciente."
                    )
                    return redirect('panel_paciente')

                box_libre = BoxAtencion.objects.filter(estado_box=True).first()
                if not box_libre:
                    box_libre = BoxAtencion.objects.create(numero_box=101, piso=1, estado_box=True)

                nueva_cita = CitaMedica.objects.create(
                    paciente=paciente,
                    medico=horario.medico,
                    box=box_libre,
                    horario=horario,
                    estado='Confirmada'
                )
                horario.estado_disponibilidad = False
                horario.save()

                messages.success(request, "¡Excelente! Su hora médica quedó reservada con éxito.")
                return redirect('comprobante_cita', cita_id=nueva_cita.id)

        elif accion == 'anular':
            cita_id = request.POST.get('cita_id')
            cita = get_object_or_404(CitaMedica, id=cita_id, paciente=paciente)
            if cita.estado == 'Confirmada':
                horario = cita.horario
                horario.estado_disponibilidad = True
                horario.save()
                cita.delete()
                messages.info(
                    request,
                    "Su cita fue anulada correctamente y el horario quedó libre nuevamente."
                )
            return redirect('panel_paciente')

    mis_citas = CitaMedica.objects.filter(paciente=paciente).select_related(
        'medico', 'medico__especialidad', 'box', 'horario'
    ).order_by('-horario__fecha')

    mis_recetas = HistorialClinico.objects.filter(paciente=paciente).select_related(
        'medico', 'medico__especialidad'
    ).order_by('-fecha_registro')

    return render(request, 'clinica/panel_paciente.html', {
        'paciente': paciente,
        'especialidades': Especialidad.objects.all(),
        'especialidad_seleccionada': int(especialidad_id) if (especialidad_id and especialidad_id.isdigit()) else None,
        'horarios_disponibles': horarios_disponibles,
        'mis_citas': mis_citas,
        'mis_recetas': mis_recetas,
        'rol_actual': 'PACIENTE'
    })


@login_required(login_url='login')
def comprobante_cita(request, cita_id):
    """RF-05: Genera el comprobante digital de la cita médica reservada."""
    cita = get_object_or_404(CitaMedica, id=cita_id)
    rol = obtener_rol_usuario(request.user)

    if rol == 'PACIENTE' and cita.paciente != request.user.paciente:
        messages.error(request, "No tiene permiso para ver el comprobante de otro paciente.")
        return redirect('panel_paciente')

    return render(request, 'clinica/comprobante.html', {
        'cita': cita,
        'rol_actual': rol
    })


@login_required(login_url='login')
def panel_medico(request):
    """Panel exclusivo para el rol MEDICO (UC-03 y RF-04)."""
    if obtener_rol_usuario(request.user) != 'MEDICO':
        messages.warning(request, "Acceso denegado: Solo los profesionales médicos pueden acceder a fichas clínicas.")
        return redirigir_segun_rol(request.user)

    medico = request.user.medico

    if request.method == 'POST':
        cita_id = request.POST.get('cita_id')
        diagnostico = request.POST.get('diagnostico', '').strip()
        receta = request.POST.get('receta', '').strip()
        observaciones = request.POST.get('observaciones', '').strip()

        cita = get_object_or_404(CitaMedica, id=cita_id, medico=medico)

        if diagnostico:
            with transaction.atomic():
                HistorialClinico.objects.create(
                    paciente=cita.paciente,
                    medico=medico,
                    cita=cita,
                    diagnostico=diagnostico,
                    receta=receta,
                    observaciones=observaciones
                )
                cita.estado = 'Atendida'
                cita.save()
            messages.success(
                request,
                f"Ficha clínica de {cita.paciente.usuario.first_name} actualizada y guardada con éxito."
            )
        else:
            messages.error(request, "Debe escribir un diagnóstico antes de guardar la ficha clínica.")
        return redirect('panel_medico')

    citas_medico = CitaMedica.objects.filter(medico=medico).select_related(
        'paciente', 'paciente__usuario', 'box', 'horario'
    ).order_by('horario__fecha', 'horario__hora_inicio')

    historiales_previos = HistorialClinico.objects.select_related(
        'paciente', 'paciente__usuario', 'medico'
    ).order_by('-fecha_registro')

    return render(request, 'clinica/panel_medico.html', {
        'medico': medico,
        'citas_medico': citas_medico,
        'historiales_previos': historiales_previos,
        'rol_actual': 'MEDICO'
    })


@login_required(login_url='login')
def panel_recepcionista(request):
    """Panel exclusivo para el rol RECEPCIONISTA (UC-02 y UC-04)."""
    if obtener_rol_usuario(request.user) != 'RECEPCIONISTA':
        messages.warning(request, "Acceso restringido: Pantalla exclusiva para Recepción.")
        return redirigir_segun_rol(request.user)

    recepcionista = request.user.recepcionista

    if request.method == 'POST':
        accion = request.POST.get('accion')

        if accion == 'agendar_tercero':
            paciente_id = request.POST.get('paciente_id')
            horario_id = request.POST.get('horario_id')
            paciente = get_object_or_404(Paciente, id=paciente_id)
            horario = get_object_or_404(HorarioMedico, id=horario_id)

            if horario.estado_disponibilidad:
                box = BoxAtencion.objects.filter(estado_box=True).first()
                cita = CitaMedica.objects.create(
                    paciente=paciente,
                    medico=horario.medico,
                    box=box,
                    horario=horario,
                    estado='Confirmada'
                )
                horario.estado_disponibilidad = False
                horario.save()
                messages.success(
                    request,
                    f"Cita agendada exitosamente para el paciente {paciente.usuario.first_name}."
                )
                return redirect('comprobante_cita', cita_id=cita.id)

        elif accion == 'anular_cita':
            cita_id = request.POST.get('cita_id')
            cita = get_object_or_404(CitaMedica, id=cita_id)
            horario = cita.horario
            horario.estado_disponibilidad = True
            horario.save()
            cita.delete()
            messages.info(request, "Cita anulada por recepción.")
            return redirect('panel_recepcionista')

    return render(request, 'clinica/panel_recepcionista.html', {
        'recepcionista': recepcionista,
        'pacientes': Paciente.objects.select_related('usuario').all(),
        'horarios_libres': HorarioMedico.objects.filter(estado_disponibilidad=True).select_related('medico', 'medico__especialidad'),
        'todas_las_citas': CitaMedica.objects.select_related('paciente', 'medico', 'box', 'horario').order_by('horario__fecha'),
        'rol_actual': 'RECEPCIONISTA'
    })


@login_required(login_url='login')
def panel_admin(request):
    """Panel exclusivo para el rol ADMINISTRADOR (Historia de Usuario SCRUM-13)."""
    if obtener_rol_usuario(request.user) != 'ADMIN':
        messages.warning(request, "Acceso restringido: Pantalla exclusiva para Administración del Sistema.")
        return redirigir_segun_rol(request.user)

    if request.method == 'POST':
        tipo_form = request.POST.get('tipo_form')

        if tipo_form == 'nuevo_box':
            numero_box = request.POST.get('numero_box')
            piso = request.POST.get('piso')
            if numero_box and not BoxAtencion.objects.filter(numero_box=numero_box).exists():
                BoxAtencion.objects.create(numero_box=numero_box, piso=piso or 1, estado_box=True)
                messages.success(request, f"Box N° {numero_box} creado correctamente.")
            else:
                messages.error(request, "Ese número de Box ya existe.")

        elif tipo_form == 'nueva_especialidad':
            nombre = request.POST.get('nombre', '').strip()
            descripcion = request.POST.get('descripcion', '').strip()
            if nombre and not Especialidad.objects.filter(nombre__iexact=nombre).exists():
                Especialidad.objects.create(nombre=nombre, descripcion=descripcion)
                messages.success(request, f"Especialidad '{nombre}' agregada al sistema.")

        elif tipo_form == 'nuevo_horario':
            medico_id = request.POST.get('medico_id')
            fecha = request.POST.get('fecha')
            hora_inicio = request.POST.get('hora_inicio')
            hora_fin = request.POST.get('hora_fin')
            if medico_id and fecha and hora_inicio and hora_fin:
                medico = get_object_or_404(Medico, id=medico_id)
                HorarioMedico.objects.create(
                    medico=medico,
                    fecha=fecha,
                    hora_inicio=hora_inicio,
                    hora_fin=hora_fin,
                    estado_disponibilidad=True
                )
                messages.success(request, f"Nuevo bloque horario habilitado para {medico}.")

        return redirect('panel_admin')

    return render(request, 'clinica/panel_admin.html', {
        'especialidades': Especialidad.objects.all(),
        'boxes': BoxAtencion.objects.all().order_by('numero_box'),
        'medicos': Medico.objects.select_related('usuario', 'especialidad').all(),
        'horarios': HorarioMedico.objects.select_related('medico').order_by('-fecha', 'hora_inicio'),
        'rol_actual': 'ADMIN'
    })


def cargar_datos_demo(request):
    """
    Carga masiva completa de datos de prueba para SIGMAC.
    Garantiza que todas las cuentas queden con la clave 'clave1234'.
    """
    with transaction.atomic():
        # 1. Especialidades
        esp_gen, _ = Especialidad.objects.get_or_create(nombre="Medicina General y Adulto Mayor", defaults={"descripcion": "Chequeos integrales"})
        esp_card, _ = Especialidad.objects.get_or_create(nombre="Cardiología", defaults={"descripcion": "Cuidado cardiovascular"})
        esp_oft, _ = Especialidad.objects.get_or_create(nombre="Oftalmología", defaults={"descripcion": "Evaluación visual"})
        esp_ped, _ = Especialidad.objects.get_or_create(nombre="Pediatría", defaults={"descripcion": "Atención infantil"})
        esp_der, _ = Especialidad.objects.get_or_create(nombre="Dermatología", defaults={"descripcion": "Afecciones en la piel"})
        esp_tra, _ = Especialidad.objects.get_or_create(nombre="Traumatología", defaults={"descripcion": "Lesiones y articulaciones"})

        # 2. Boxes
        BoxAtencion.objects.get_or_create(numero_box=101, defaults={'piso': 1, 'estado_box': True})
        BoxAtencion.objects.get_or_create(numero_box=102, defaults={'piso': 1, 'estado_box': True})

        # 3. Administrador
        user_adm, _ = User.objects.get_or_create(username="44.444.444-4", defaults={'first_name': 'Samantha', 'last_name': 'Bolognesi', 'email': 'admin@clinicontrol.cl'})
        user_adm.set_password("clave1234")
        user_adm.save()
        Administrador.objects.get_or_create(usuario=user_adm, defaults={'rut': '44.444.444-4', 'nivel_acceso': 10})

        # 4. Recepcionistas (Las 4)
        datos_recepcionistas = [
            ("33.333.333-3", "Marcela", "Pinto", "recepcion1@clinicontrol.cl", "Mañana (08:00 a 14:00)"),
            ("34.444.444-4", "Camila", "Soto", "recepcion2@clinicontrol.cl", "Tarde (14:00 a 20:00)"),
            ("35.555.555-5", "Javier", "Morales", "recepcion3@clinicontrol.cl", "Vespertino (16:00 a 22:00)"),
            ("36.666.666-6", "Valentina", "Rojas", "recepcion4@clinicontrol.cl", "Fin de Semana / Reemplazos"),
        ]
        for rut_r, nom_r, ape_r, mail_r, turno_r in datos_recepcionistas:
            u_r, _ = User.objects.get_or_create(username=rut_r, defaults={'first_name': nom_r, 'last_name': ape_r, 'email': mail_r})
            u_r.set_password("clave1234")
            u_r.save()
            Recepcionista.objects.get_or_create(usuario=u_r, defaults={'rut': rut_r, 'turno': turno_r})

        # 5. Médicos
        datos_medicos = [
            ("22.222.222-2", "Carlos", "Soto", "csoto@clinicontrol.cl", esp_gen, "REG-8841"),
            ("23.232.323-3", "Elena", "Valdés", "evaldes@clinicontrol.cl", esp_card, "REG-9920"),
            ("24.242.424-4", "Fernando", "Araya", "faraya@clinicontrol.cl", esp_oft, "REG-1034"),
            ("25.252.252-5", "Patricia", "Muñoz", "pmunoz@clinicontrol.cl", esp_ped, "REG-1198"),
            ("26.262.262-6", "Gonzalo", "Tapia", "gtapia@clinicontrol.cl", esp_der, "REG-1350"),
            ("27.272.272-7", "Sofía", "Ramírez", "sramirez@clinicontrol.cl", esp_tra, "REG-1420"),
        ]
        medicos_objs = []
        for rut_m, nom_m, ape_m, mail_m, esp_m, reg_m in datos_medicos:
            u_m, _ = User.objects.get_or_create(username=rut_m, defaults={'first_name': nom_m, 'last_name': ape_m, 'email': mail_m})
            u_m.set_password("clave1234")
            u_m.save()
            med_obj, _ = Medico.objects.get_or_create(usuario=u_m, defaults={'rut': rut_m, 'especialidad': esp_m, 'numero_registro_salud': reg_m})
            medicos_objs.append(med_obj)

        # 6. Pacientes
        datos_pacientes = [
            ("11.111.111-1", "Rosa", "González", "rosa@correo.cl", date(1952, 5, 14), "+56987654321", "FONASA"),
            ("12.222.222-2", "Juan", "Pérez", "juan.perez@correo.cl", date(1985, 3, 22), "+56911223344", "FONASA"),
            ("13.333.333-3", "María", "Tapia", "mtapia@correo.cl", date(1990, 8, 10), "+56955667788", "ISAPRE"),
        ]
        for rut_p, nom_p, ape_p, mail_p, fnac_p, fono_p, prev_p in datos_pacientes:
            u_p, _ = User.objects.get_or_create(username=rut_p, defaults={'first_name': nom_p, 'last_name': ape_p, 'email': mail_p})
            u_p.set_password("clave1234")
            u_p.save()
            Paciente.objects.get_or_create(usuario=u_p, defaults={'rut': rut_p, 'fecha_nacimiento': fnac_p, 'telefono': fono_p, 'prevision': prev_p})

        # 7. Horarios Médicos
        hoy = date.today()
        for d in range(1, 4):
            fecha_slot = hoy + timedelta(days=d)
            for med in medicos_objs:
                HorarioMedico.objects.get_or_create(
                    medico=med, fecha=fecha_slot, hora_inicio=time(9, 30),
                    defaults={'hora_fin': time(10, 0), 'estado_disponibilidad': True}
                )

    messages.success(request, "¡Datos de demostración actualizados con éxito!")
    return redirect('login')