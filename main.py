import pandas as pd
import glob
from datetime import datetime, timedelta



# ---------------------------------------------------------------------------------
# principal function
# ---------------------------------------------------------------------------------

def analyze_all_alerts():
        print('\n****** Inicio ******')
        df_attacklog = get_last_dfattacklog()
        df_dbrecurringalerts = get_dfdbrecurringalerts()
        # print(dfdbrecurringalerts.columns)       
        get_new_inconclusive_incidents(df_attacklog,df_dbrecurringalerts)
        get_new_none_inconclusive_incidents(df_attacklog,df_dbrecurringalerts)
        get_known_incidents(df_attacklog,df_dbrecurringalerts) 
        get_top_attacker_ip(df_attacklog)   
        
# ---------------------------------------------------------------------------------
# Modulos
# ---------------------------------------------------------------------------------
        
# obtengo los eventos nuevos que no estan en la db y el result es inconclusive
def get_new_inconclusive_incidents(dfnewlogs, dfdatabase):
    # Filtrar para obtener solo las filas donde el status es 'inconclusive'
    df_new_inconclusive = dfnewlogs[(dfnewlogs['Result'] == 'Inconclusive') & ~(dfnewlogs['Name'].isin(dfdatabase['Event']))]
    # Convertir la columna 'd' a tipo datetime
    df_new_inconclusive['Time'] = pd.to_datetime(df_new_inconclusive['Time'], format='%a %b %d %H:%M:%S UTC %Y')
    # Ordenar por 'Name' y 'Time' para asegurarse de que los registros más recientes estén al final
    df_new_inconclusive.sort_values(by=['Name', 'Time'], inplace=True)
    # Obtener el último registro de cada 'Name'
    df_new_inconclusive = df_new_inconclusive.drop_duplicates(subset='Name', keep='last')


    print("\033[34m" + '****** nuevos incidentes inconclusive ******' + "\033[0m")
    # Verificar si el DataFrame se considera "vacío" según nuestra definición
    if df_new_inconclusive.empty or len(df_new_inconclusive) == 0:
        print("\033[92m" + "Sin resultados" + "\033[0m")
    else:
        print(df_new_inconclusive)

 
# obtengo los eventos nuevos que no estan en la db y supera la cantidad de 1
def get_new_none_inconclusive_incidents(dfnewlogs, dfdatabase):
    cantidad = 1
    # Filtrar para obtener solo las filas donde el status es distinto a 'inconclusive' y que no esten en la db
    df_new_none_inconclusive = dfnewlogs[(dfnewlogs['Result'] != 'Inconclusive') & ~(dfnewlogs['Name'].isin(dfdatabase['Event']))]
    # Agrupar por 'name' y filtrar los grupos con más de 2 elementos
    df_new_none_inconclusive_filter = df_new_none_inconclusive.groupby('Name').filter(lambda x: len(x) > cantidad)

    # Convertir la columna 'Time' a tipo datetime
    df_new_none_inconclusive_filter['Time'] = pd.to_datetime(df_new_none_inconclusive_filter['Time'], format='%a %b %d %H:%M:%S UTC %Y')
    # Ordenar por 'Name' y 'Time' para asegurarse de que los registros más recientes estén al final
    df_new_none_inconclusive_filter.sort_values(by=['Name', 'Time'], inplace=True)
    # Obtener el último registro de cada 'Name'
    df_new_none_inconclusive_filter = df_new_none_inconclusive_filter.drop_duplicates(subset='Name', keep='last')

    print("\033[34m" + '****** nuevos incidentes no inconclusive > 1 alertas ******' + "\033[0m")
    # Verificar si el DataFrame se considera "vacío" según nuestra definición
    if df_new_none_inconclusive_filter.empty or len(df_new_none_inconclusive_filter) == 0:
        print("\033[92m" + "Sin resultados" + "\033[0m")
    else:
        print(df_new_none_inconclusive_filter)
    
 
# obtengo los eventos que estan en la db y la cantidad supera 24
def get_known_incidents(dfnewlogs, dfdatabase): 
    cantidad = 24
    # Filtrar para obtener solo las filas donde el status es distinto a 'inconclusive' y que no esten en la db
    df_known_incidents = dfnewlogs[(dfnewlogs['Name'].isin(dfdatabase['Event']))]
    # Agrupar por 'name' y filtrar los grupos con más de 24 elementos
    df_known_incidents_filter = df_known_incidents.groupby('Name').filter(lambda x: len(x) > cantidad)

    # Convertir la columna 'Time' a tipo datetime
    df_known_incidents_filter['Time'] = pd.to_datetime(df_known_incidents_filter['Time'], format='%a %b %d %H:%M:%S UTC %Y')
    # Ordenar por 'Name' y 'Time' para asegurarse de que los registros más recientes estén al final
    df_known_incidents_filter.sort_values(by=['Name', 'Time'], inplace=True)
    # Obtener el último registro de cada 'Name'
    df_known_incidents_filter = df_known_incidents_filter.drop_duplicates(subset='Name', keep='last')

    print("\033[34m" + '****** Incidentes recurrentes superior a 24 ******' + "\033[0m")
    # Verificar si el DataFrame se considera "vacío" según nuestra definición
    if df_known_incidents_filter.empty or len(df_known_incidents_filter) == 0:
        print("\033[92m" + "Sin resultados" + "\033[0m")
    else:
        print(df_known_incidents_filter)

# genera formato para service now
def generate_ticket():
    pass

# obtengo los eventos nuevos que no estan en la db y el result es inconclusive
def get_top_attacker_ip(dfnewlogs):

    # Convertir la columna 'Time' a tipo datetime
    dfnewlogs['Time'] = pd.to_datetime(dfnewlogs['Time'], format='%a %b %d %H:%M:%S UTC %Y')

    # creo dataframe aux
    df_time_attackerip = dfnewlogs[['Time', 'Attacker IP Address']]
    #df_time_attackerip = dfnewlogs

    # Aplicar la función a cada fila de df1 y crear una nueva columna con el conteo
    dfnewlogs['occurrences'] = dfnewlogs.apply(lambda row: count_occurrences(row, df_time_attackerip,'Time',1), axis=1)

    # Agrupar por avión y seleccionar la fila con el valor más alto de 'c' para cada avión
    df_topten_attackerip = dfnewlogs.sort_values('occurrences', ascending=False).drop_duplicates(subset=['Attacker IP Address']).reset_index(drop=True)
    df_topten_attackerip = df_topten_attackerip[['occurrences','Time', 'Attacker IP Address', 'Name']].head(10)
        
    print("\033[34m" + '****** Top 10 attacker IPs in less than 2 minutes ******' + "\033[0m")
    # Verificar si el DataFrame se considera "vacío" según nuestra definición
    if df_topten_attackerip.empty or len(df_topten_attackerip) == 0:
         print("\033[92m" + "Sin resultados" + "\033[0m")
    else:
         print(df_topten_attackerip)

# Función para contar ocurrencias en un intervalo de tiempo
def count_occurrences(row, df2,column,interval):
    start_time = row[column] - timedelta(minutes=interval)
    end_time = start_time + timedelta(minutes=interval)
    count = df2[(df2['Attacker IP Address'] == row['Attacker IP Address']) & (df2[column] >= start_time) & (df2[column] < end_time)].shape[0]
    return count

# ---------------------------------------------------------------------------------
# Funciones secundarias
# ---------------------------------------------------------------------------------

def get_last_dfattacklog():
    # se crea el path
    my_script_path = r'C:\Users\Usuario\Documents\Main\Programing\trellix_alerts'
    attacklog_path = my_script_path + r'\attackLog\AttackLog*'
    # buscamos el ultimo csv log
    archivos_attacklog = sorted(glob.glob(attacklog_path))
    if archivos_attacklog:
        attacklog_file = archivos_attacklog[-1]
        print("\n\033[92m" + 'Path: ' + attacklog_file + "\033[0m\n")
        # creo el data frame del csv
        return pd.read_csv(attacklog_file, skiprows=2)
    else:
        print("No se encontraron archivos que comiencen con 'AttackLog'")
        return None

def get_dfdbrecurringalerts():
    # se crea el path
    my_script_path = r'C:\Users\Usuario\Documents\Main\Programing\trellix_alerts'
    db_path = my_script_path + r'\data\database\*'
    # buscamos el ultimo csv log
    database_path = sorted(glob.glob(db_path))
    if database_path:
        database_file = database_path[-1]
        
        # creo el data frame del csv
        return pd.read_csv(database_file)
    else:
        print("No se encontro la base de datos")
        return None

# ---------------------------------------------------------------------------------
# Bloque main
# ---------------------------------------------------------------------------------
        
if __name__ == "__main__":
    analyze_all_alerts()
