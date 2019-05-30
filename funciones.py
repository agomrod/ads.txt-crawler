
import requests
import csv
import time
import pandas as pd
import numpy as np
import os
from py2neo import *
import collections
import seaborn as sns
import matplotlib.pyplot as plt
from scipy import stats
import pyprind
import operator

#with open('Ads-txt site list.csv', newline='') as File:
#    reader = csv.reader(File)
#    for row in reader:
#        urls.append(row)

def urls_read(domainlist_filename, num):
    raw_urls = []
    i = 1
    file = open(domainlist_filename,'r')
    line = file.readline()
    while line != '' and i <= num:
        raw_urls.append(line)
        line = file.readline()
        i+=1
    return raw_urls

def url_text_add(text, raw_urls):
    urls = []
    for url in raw_urls:
        url = url.strip()
        urls.append( text + url + '/ads.txt')
    return urls

def save_info_crawler(num_urls, timeouts, httperrors, lib_errors, downloads, notfound, numredirs, date, inicio, fin):
    with open(date + '/info/info.txt', 'a') as info:
        info.write("CRAWLER")
        info.write("Urls comprobadas: " + str(num_urls) + "\n")
        info.write("Ficheros ads.tx descargados:" + str(downloads) + "(" + str((downloads/num_urls)*100) + "%)\n")
        info.write("Ficheros ads.txt no encontrados: " + str(notfound) + " (" + str((notfound/num_urls)*100) + "%)\n")
        info.write("HTTPErrors: " + str(httperrors) + " (" + str((httperrors/num_urls)*100) + "%)\n")
        info.write("Timeouts: " + str(timeouts) + " (" +  str((timeouts/num_urls)*100) + "%)\n")
        info.write("RequestLibraryErrors: " + str(lib_errors) + " (" + str((lib_errors/num_urls)*100) + "%)\n")
        elapsed = fin - inicio
        info.write('time: ' + str(elapsed) + 's\n')

def save_info_parser(date, inicio, fin):
    with open(date + '/info/info.txt', 'a') as info:
        info.write("PARSER")
        elapsed = fin - inicio
        info.write('time: ' + str(elapsed) + 's\n')


def print_info_crawler(num_urls, timeouts, httperrors,lib_errors, downloads, notfound, numredirs, inicio, fin):
    print("Urls comprobadas: " + str(num_urls) + '                 ')
    print("Ficheros ads.tx descargados:" + str(downloads) + " (" + str((downloads/num_urls)*100) + "%)")
    print("Ficheros ads.txt no encontrados: " + str(notfound) + " (" + str((notfound/num_urls)*100) + "%)")
    print("HTTPErrors: " + str(httperrors) + " (" + str((httperrors/num_urls)*100) + "%)")
    print("Timeouts: " + str(timeouts) + " (" + str((timeouts/num_urls)*100) + "%)")
    print("RequestLibraryErrors: " + str(lib_errors) + " (" + str((lib_errors/num_urls)*100) + "%)")
    elapsed = fin - inicio
    print('time: ' + str(elapsed) + 's')
    #print("Número medio de redirecciones: " + str(sum(numredirs)/len(numredirs)))

def mkdir(name):
    try:
        os.mkdir(name)
    except OSError:
        print ("Error creando directorio " + name)
    return 0

def draw_histogram(data):
    sns.set(color_codes=True)
    sns.distplot(data, kde = True ,hist=True, rug=False);


def my_crawler(urls, date, timeout, start):
    comp = 'ads.txt'
    timeouts = 0
    httperrors = 0
    lib_errors = 0
    notfound = 0
    numredirs = 0
    valid_urls = []
    last_modified = []
    adsurls = []
    noadsurls = []
    redirs = []
    found_flag = []
    num_redirs_list = []
    i=1

    #bar = pyprind.ProgBar(len(urls), monitor = True, title = 'Crawler')
    for url_inicial in urls:
        print(str(i) + "/"+ str(len(urls)) + " Urls Comprobadas", end='\r')
        i+=1

        try:
            r = requests.get(url_inicial, timeout=timeout)
            r.raise_for_status()

        except requests.exceptions.Timeout as e:
            timeouts += 1
            #print("TIMEOUT ERROR")
            noadsurls.append(url_inicial.split("/")[2])
            with open(date + '/errors/timeoutLog.txt', 'a') as log:
               log.write("{}\n".format(e))
            continue

        except requests.exceptions.HTTPError as e:
            httperrors += 1
            #print("HTTP ERROR")
            noadsurls.append(url_inicial.split("/")[2])
            with open(date + '/errors/HTTPErrorLog.txt', 'a') as log:
                log.write("{}\n".format(e))
            continue

        except requests.exceptions.RequestException as e:
            lib_errors += 1
            #print("LIB ERROR")
            noadsurls.append(url_inicial.split("/")[2])
            with open(date + '/errors/lib_errors.txt', 'a') as log:
               log.write("{}\n".format(e))
            continue

        if r.status_code == 200:
            #print("GUAY")
            redirecciones = []
            url_final = r.url
            valid_urls.append(url_inicial)
            if 'Last-Modified' in r.headers:
                    last_modified.append(r.headers['last-modified'])
            else:
                    last_modified.append('')

            for x in range (0,len(r.history)):
              redirecciones.append(r.history[x].headers['location'])

            redirs_str = ','.join(redirecciones)
            redirs.append(redirs_str)

            if len(r.history) != 0:
                num_redirs = len(r.history)
            else:
                num_redirs = 0

            num_redirs_list.append(num_redirs)

            comprobacion = url_final[len(url_final) - 7 : len(url_final)]

            if comprobacion == comp:
                with open(date + "/ads_txt/ads_"+url_inicial.split("/")[2]+"_.txt",'wb') as f:
                    f.write(r.content)
                adsurls.append(url_inicial.split("/")[2])
                found_flag.append(1)
            else:
                found_flag.append(0)
                notfound += 1
                noadsurls.append(url_inicial.split("/")[2])
        else:
            pass

    last_modified_data = {'url': valid_urls,
                          'last_modified': last_modified}

    redirs_data = {'url': valid_urls,
                   'num_redirs' : num_redirs_list,
                   'redirs' : redirs,
                   'found_flag' : found_flag}

    last_modified_df = pd.DataFrame(last_modified_data, columns = ['url',
                                                                   'last_modified'])

    redirs_df = pd.DataFrame(redirs_data, columns = ['url',
                                                     'num_redirs',
                                                     'redirs',
                                                     'found_flag'])

    last_modified_df.to_csv(date + '/info/last_modified.csv',index=False)
    redirs_df.to_csv(date + '/redirecciones/redirs_info.csv',index=False)

    fin = time.time()
    print_info_crawler(len(urls), timeouts, httperrors, lib_errors, len(adsurls), notfound, numredirs, start, fin)
    save_info_crawler(len(urls), timeouts, httperrors, lib_errors, len(adsurls), notfound, numredirs, date, start, fin)

    return adsurls, noadsurls

def is_singular(matrix):
    return matrix.shape[0] == matrix.shape[1] and np.linalg.matrix_rank(matrix) == matrix.shape[0]

def get_publisher_adstxt(dic, date):

    dic_publishers = {}
    directs_list_pub = []
    resellers_list_pub = []

    for key in dic:

        accountTypesPublisher = []
        len_test = 0
        num_directs_publisher=0
        num_resellers_publisher=0
        df_publisher = pd.DataFrame(columns = ['ad_system',
                                               'seller_account_id',
                                               'account_type',
                                               'certification_authority_id'])

        if key == 'Independientes':
            continue

        k=0

        for linea in dic.get(key):
            data = pd.read_csv(date + '/ads_txt_csv/adstxt_(' + linea + ').csv')

            df = pd.DataFrame(data, columns = ['ad_system',
                                               'seller_account_id',
                                               'account_type',
                                               'certification_authority_id'])

            len_test = len_test + len(df)

            df_publisher = pd.concat([df_publisher,df], ignore_index=True)

            k = k+1

        print('Test de concatenación correcta: ' + str(len_test == len(df_publisher)))

        df_publisher.drop_duplicates(keep='first', inplace=True)

        df_publisher.to_csv(date + '/ads_txt_publisher/adstxt_('+ key + ').csv',index=False)

        accountTypesPublisher = df_publisher['account_type'].tolist()

        for i in range(0,len(accountTypesPublisher)):

            if(len(str(accountTypesPublisher[i])) != 6):
                if accountTypesPublisher[i][0:8] == "RESELLER":
                    num_resellers_publisher += 1

                elif accountTypesPublisher[i][0:6] == "DIRECT":
                    num_directs_publisher += 1

            else:
                if accountTypesPublisher[i] == "DIRECT":
                    num_directs_publisher += 1

        directs_list_pub.append(num_directs_publisher)
        resellers_list_pub.append(num_resellers_publisher)

        dic_publishers[key] = df;

    info_publishers = {'num_directs': directs_list_pub,
                       'num_resellers': resellers_list_pub}

    df_info_publisher = pd.DataFrame(info_publishers, columns = ['num_directs',
                                                                 'num_resellers'])

    df_info_publisher.to_csv(date + '/info/num_sellers_publisher.csv',index=False)

    return dic_publishers, info_publishers

def my_parser(graph, adsurls, date, start):

    certificationAuthorityID = ''
    comentarios = ''
    no_pillaos = 0
    num_directs=0
    num_resellers=0
    directs_list = []
    resellers_list = []
    ads_dataframes_list = []
    no_entendidos = []
    comments = []
    adSystemsClean = []
    accountTypesClean = []
    count = 0

    for url in adsurls:
        adSystems = []
        sellerAcountIDs = []
        accountTypes = []
        certificationAuthorityIDs = []
        num_directs=0
        num_resellers=0
        # publisher = Node("Publisher", url=adsurls)
        # graph.create(publisher)

        with open(date + '/info/matrix_legend.txt', 'a') as info:
            info.write(str(count) + ' - ' + url + "\n")
        count+=1

        fichero = open(date + '/ads_txt/ads_' + url + '_.txt','r', errors='ignore')

        for linea in fichero:

            if len(linea.split(',')) < 3:
                pass

            else:
                adSystems.append(linea.split(',')[0].strip())
                sellerAcountIDs.append(linea.split(',')[1].strip())
                accountTypes.append(linea.split(',')[2].strip().upper())

                if len(linea.split(',')) == 4 or len(linea.split(',')) == 5:
                    certificationAuthorityIDs.append(linea.split(',')[3].strip())

                else:
                    certificationAuthorityIDs.append('')

                # if len(linea.split(',')) == 5:
                #     certificationAuthorityIDs.append(linea.split(',')[3].strip())
                #     comments.append(linea.split(',')[4].strip())
                #
                # else:
                #     comments.append('')

        for i in range(0,len(adSystems)):

            if(len(accountTypes[i]) != 6):
                if accountTypes[i][0:8] == "RESELLER":
                    #node = Node("Reseller", url=adSystems[i], accountID = sellerAcountIDs[i])
                    #relacion = "RESELLER"
                    num_resellers += 1

                elif accountTypes[i][0:6] == "DIRECT":
                    #node = Node("Direct", url=adSystems[i], accountID = sellerAcountIDs[i])
                    #relacion = "DIRECT"
                    num_directs += 1

                else:
                    no_pillaos += 1
                    no_entendidos.append(accountTypes[i])
                    pass

            else:
                if accountTypes[i] == "DIRECT":
                    #node = Node("Direct", url=adSystems[i], accountID = sellerAcountIDs[i])
                    #relacion = "DIRECT"
                    num_directs += 1

                else:
                    no_pillaos += 1
                    no_entendidos.append(accountTypes[i])
                    pass

        directs_list.append(num_directs)
        resellers_list.append(num_resellers)

        # counts_por_elem = collections.Counter(adSystems)
        #
        # indices_por_elem = collections.defaultdict(list)
        # indices = []
        #
        # for indice, elem in enumerate(adSystems):
        #   if counts_por_elem[elem] > 1:
        #     indices.append(indice)
        #     indices_por_elem[elem].append(indice)
        #
        # print(indices_por_elem)
        # print(counts_por_elem)


        data = {'ad_system': adSystems,
                'seller_account_id' : sellerAcountIDs,
                'account_type': accountTypes,
                'certification_authority_id': certificationAuthorityIDs}

        df = pd.DataFrame(data, columns = ['ad_system',
                                            'seller_account_id',
                                            'account_type',
                                            'certification_authority_id'])

        ads_dataframes_list.append(df.drop_duplicates(subset = 'seller_account_id', keep = False))  # keep = 'first'?????


        df.to_csv(date + '/ads_txt_csv/adstxt_('+ url + ').csv',index=False)

    similarity_matrix = [[0 for x in range(len(ads_dataframes_list))] for y in range(len(ads_dataframes_list))]

    for i in range(0,len(ads_dataframes_list)):
        for j in range(i,len(ads_dataframes_list)):
            #lineas_iguales = pd.merge(ads_dataframes_list[i], ads_dataframes_list[j], on=['ad_system','seller_account_id','account_type','certification_authority_id'], how='inner', copy=False)
            concat = pd.concat([ads_dataframes_list[i], ads_dataframes_list[j]])

            totales = len(concat)
            lineas_distintas = concat.drop_duplicates(keep=False)
            coincidentes = (totales - len(lineas_distintas))/2

            if(min(len(ads_dataframes_list[i]),len(ads_dataframes_list[j]))) !=0:
                porcentaje = (coincidentes/min(len(ads_dataframes_list[i]),len(ads_dataframes_list[j])))*100
                similarity_matrix[i][j] = porcentaje

            else:
                similarity_matrix[i][j] = 0

    similarity_vector = []
    colum_ya_miradas = []
    dic_grupos = {}
    dic_grupos['Independientes'] = []

    k = 0
    for i in range(0,len(ads_dataframes_list)):
        lista_grupos = []
        lista_grupos.append(adsurls[i])
        for j in range(i,len(ads_dataframes_list)):                     #Si hago esto en la matriz ahorro tiempo???
            if(i != j):                                                 #Eliminamos las comparaciones de un archivo consigo mismo
                similarity_vector.append(similarity_matrix[i][j])       #para no coger valores = 100 falsos.
                if(similarity_matrix[i][j] > 80):
                    if((i in colum_ya_miradas) == False):
                        lista_grupos.append(adsurls[j])
                        colum_ya_miradas.append(j)
        if(len(lista_grupos) > 1):
            dic_grupos['Publisher%d'%k] = lista_grupos
            k += 1
        elif((i in colum_ya_miradas) == False):
            dic_grupos.get('Independientes').append(adsurls[i])

    resultado = sorted(dic_grupos.items(), key=operator.itemgetter(0))

    dic_publishers, info_publishers = get_publisher_adstxt(dic_grupos, date)

    pub_directs = info_publishers.get('num_directs')
    pub_resellers = info_publishers.get('num_resellers')

    with open(date + '/info/groups.txt', 'a') as groups:
        for k, v in resultado:
            groups.write("{}\n".format(k + '\n\t' + str(v)))

        for k in dic_grupos:
            groups.write("{}\n".format(k + " : " + str(len(dic_grupos.get(k)))))

    #print(resultado)
    #print(similarity_vector)

    with open(date + '/errors/cuentas_no_pilladas.txt', 'a') as log:
        log.write("{}\n".format('No he pillado ' + str(no_pillaos) + ' tipos de cuenta:'))
        for tipo in no_entendidos:
            log.write("{}\n".format(tipo))

    data_publisher = {'publisher': adsurls,
                      'num_directs': directs_list,
                      'num_resellers': resellers_list}


    d_pub = pd.DataFrame(data_publisher, columns = ['publisher',
                                                    'num_directs',
                                                    'num_resellers'])

    d_pub.to_csv(date + '/info/num_sellers.csv',index=False)

    matrix_df = pd.DataFrame(similarity_matrix)

    matrix_df.to_csv(date + '/info/similarity_matrix.csv')

    sns.set(color_codes=True)
    if len(directs_list)>1:
        plt.figure()
        a = sns.distplot(d_pub['num_directs'], kde = True ,hist=True, rug=False, label='Histograma DIRECTS', color='red');
        fig = a.get_figure()
        fig.savefig(date + '/info/directs_hist.png')
    if len(resellers_list)>1:
        plt.figure()
        b = sns.distplot(d_pub['num_resellers'], kde = True ,hist=True, rug=False, label='Histograma RESELLERS');
        fig = b.get_figure()
        fig.savefig(date + '/info/resellers_hist.png')
    if len(similarity_vector)>1:
        plt.figure()
        c = sns.distplot(similarity_vector, kde = True ,hist=True, rug=False, label='Hitograma Similarity', color='green');
        fig = c.get_figure()
        fig.savefig(date + '/info/similarity_hist.png')
    if len(pub_directs)>1:
        plt.figure()
        d = sns.distplot(pub_directs, kde = True ,hist=True, rug=False, label='Hitograma DIRECTS PUBLISHERS', color='black');
        fig = d.get_figure()
        fig.savefig(date + '/info/pub_directs_hist.png')
    if len(pub_resellers)>1:
        plt.figure()
        e = sns.distplot(pub_resellers, kde = True ,hist=True, rug=False, label='Hitograma RESELLERS PUBLISHERS', color='yellow');
        fig = c.get_figure()
        fig.savefig(date + '/info/pub_resellers_hist.png')

    fin = time.time()
    save_info_parser(date, start, fin)



        # for i in range(0,len(adSystems)):
        #     if(len(accountTypes[i]) != 6):
        #
        #         if accountTypes[i][0:8] == "RESELLER":
        #             node = Node("Reseller", url=adSystems[i], accountID = sellerAcountIDs[i])
        #             relacion = "RESELLER"
        #
        #         elif linea.split(',')[2].strip().upper()[0:6] == "DIRECT":
        #             node = Node("Direct", url=adSystems[i], accountID = sellerAcountIDs[i])
        #             relacion = "DIRECT"
        #
        #         else:
        #             no_pillaos += 1
        #             no_entendidos.append(accountTypes[i])
        #             pass
        #
        #     else:
        #
        #         if linea.split(',')[2].strip().upper()[0:6] == "DIRECT":
        #             node = Node("Direct", url=adSystems[i], accountID = sellerAcountIDsPublisher[i])
        #             relacion = "DIRECT"
        #
        #         else:
        #             no_pillaos += 1
        #             no_entendidos.append(accountTypes[i])
        #             pass
            # graph.create(node)
            # r = Relationship(publisher, relacion, node)
            # graph.create(r)
