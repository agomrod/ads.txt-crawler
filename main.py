import argparse
import time
import requests

from funciones import *

def main():
    start = time.time()

    parser = argparse.ArgumentParser(description="Crawler and Parser for ads.txt files")

    parser.add_argument('path', help="Path to the url list")
    parser.add_argument('urls', help="Number of urls you want to analyze", type=int)
    parser.add_argument('timeout', help="Timeout (s) for the requests", type=float)
    arguments = vars(parser.parse_args())


    date = time.strftime("%d-%m-%Y")
    print("Creando carpetas.")
    mkdir(date)
    mkdir(date + '/ads_txt')
    mkdir(date + '/ads_txt_csv')
    mkdir(date + '/redirecciones')
    mkdir(date + '/info')
    mkdir(date + '/errors')
    print("Carpetas creadas.\n")

    #print("Creando grafo.")
    #graph = Graph(password='ads.txt')
    graph = 4
    #print("Grafo creado.\n")


    raw_urls = urls_read(arguments["path"], arguments['urls'])

    #urls = url_text_add('http://', raw_urls)
    www_urls = url_text_add('http://www.', raw_urls)

    print("Iniciando Crawler.")
    # for url in www_urls:
    #     print(url)
    adsurls, noadsurls = my_crawler(www_urls, date, arguments['timeout'], start)
    print("Crawler finalizado.\n")

    inicio_parser = time.time()
    print("Iniciando Parser.")
    my_parser(graph, adsurls, date)
    tiempo_parser = time.time() - inicio_parser
    print('Tiempor parser: ' + str(tiempo_parser) + 's')
    print("Parser finalizado.")

    total = time.time() - start
    print('\n TOTAL TIME: ' + str(total) + 's')





if __name__ == "__main__":
    main()
