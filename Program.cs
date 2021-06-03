using Leadtools;
using Leadtools.Document.Writer;
using Leadtools.Ocr;
using System;
using System.Diagnostics;
using System.IO;

namespace OCR_Key_Feature_SDK
{
    class Program
    {
        static void Main(string[] args)
        {

            //LeadTool Licence
            RasterSupport.SetLicense(@"C:\Users\Noha\Downloads\eval-license-files_63faf918-a88f-4660-8941-cc34a867986e\eval-license-files.lic",
                                File.ReadAllText(@"C:\Users\Noha\Downloads\eval-license-files_63faf918-a88f-4660-8941-cc34a867986e\eval-license-files.lic.key"));


            //===================Searchable PDF========================================//
            string sourceFile = @"C:\Users\Noha\Music\Files\resume-io-r-Cb6B3wmWg.tif";
            string targetFile = Path.ChangeExtension(sourceFile, "pdf");
            using(IOcrEngine ocrEngine = OcrEngineManager.CreateEngine(OcrEngineType.LEAD))
            {

                bool isValid = RasterSupport.IsLocked(RasterSupportType.PdfAdvanced);
                ocrEngine.Startup(null, null,  null, @"C:\Users\Noha\.nuget\packages\leadtools.ocr.languages.main.net\21.0.0.2\content\LEADTOOLS\OcrLEADRuntime");
                ocrEngine.AutoRecognizeManager.PreprocessPageCommands.Add(OcrAutoPreprocessPageCommand.Rotate);
                ocrEngine.AutoRecognizeManager.MaximumPagesBeforeLtd = 8;
                ocrEngine.AutoRecognizeManager.JobErrorMode = OcrAutoRecognizeManagerJobErrorMode.Continue;

                PdfDocumentOptions pdfDocumentOptions = ocrEngine.DocumentWriterInstance.GetOptions(DocumentFormat.Pdf) as PdfDocumentOptions;


                ocrEngine.AutoRecognizeManager.Run(sourceFile, targetFile, Leadtools.Document.Writer.DocumentFormat.Pdf, null, null);
            }



        }
    }
}
